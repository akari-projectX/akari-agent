package main

// Signed self-update (M6), node side: the unprivileged agent's update
// directory, the hand-over to the privileged updater and the probation
// record of a freshly installed binary.
//
// W^X: the agent's StateDirectory is writable by the agent and mounted
// noexec by systemd (>= 256, DynamicUser idmapped mounts), and it stays
// that way. The agent never executes anything it downloaded. It stages the
// verified download and an apply request here; the updater unit
// (akari-agent-update.path -> akari-agent-update.service, root) runs the
// INSTALLED, trusted binary in -apply-update mode (updater.go), which treats
// everything in this directory as untrusted: it copies the staged bytes into
// a root-only file, verifies the copy against the signed manifest with its
// own compiled-in keys and version policy, installs it atomically
// (/usr/local/bin/akari-agent, the old one kept as akari-agent.prev),
// restarts the agent and watches its self-check, rolling back on failure.
//
// Layout (<state dir>/update, 0700; files 0600):
//
//	state.json          versions this node rolled back from, a report owed
//	                    to the panel (agent-owned)
//	finals.json         final traffic counters persisted across a restart
//	staged              the verified download (never executed here)
//	apply-request.json  the request to the updater (written last: it is the
//	                    trigger the path unit watches)
//	apply-result.json   the updater's verdict (written by root, chowned to
//	                    the agent): installed / confirmed / rolled_back /
//	                    rejected / rollback_failed
//	confirmed           written by the new binary once it passed its
//	                    self-check (the updater's health signal)

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
	"akari/agent/release"
)

const (
	updateDirName   = "update"
	updateStateFile = "state.json"
	finalsFileName  = "finals.json"
	stagedName      = "staged"
	requestName     = "apply-request.json"
	resultName      = "apply-result.json"
	confirmedName   = "confirmed"

	// errUpdaterMissing is shown in the panel (rollout and node view).
	errUpdaterMissing = "updater unit missing (akari-agent-update.path): run the panel's install command (重装命令) once on this node"

	defaultSelfCheck = 5 * time.Minute
	defaultMaxBoots  = 3
	// defaultApplyWait: how long the agent waits for the updater's verdict
	// (verify + copy of the staged binary: seconds).
	defaultApplyWait = 90 * time.Second
	// defaultRestartWait: after "installed", how long the agent waits for
	// the updater's restart before it exits (systemd then starts the new
	// binary).
	defaultRestartWait = time.Minute
	maxRolledBack      = 32
	stateSchema        = 1
	requestSchema      = 1
	maxRequestSize     = 64 << 10
	maxResultSize      = 16 << 10
)

// Apply request kinds.
const (
	kindApply    = "apply"
	kindRollback = "rollback"
)

// Apply result states (the updater's verdict).
const (
	resInstalled      = "installed"
	resConfirmed      = "confirmed"
	resRolledBack     = "rolled_back"
	resRejected       = "rejected"
	resRollbackFailed = "rollback_failed"
)

// applyRequest is what the agent asks of the updater. Untrusted on the
// updater's side: everything in it is re-verified there.
type applyRequest struct {
	Schema        int                 `json:"schema"`
	Kind          string              `json:"kind"`
	RolloutID     string              `json:"rollout_id"`
	Version       string              `json:"version"`
	PanelProtocol uint32              `json:"panel_protocol"`
	Manifest      []byte              `json:"manifest,omitempty"` // signed bytes, verbatim
	Signatures    []release.Signature `json:"signatures,omitempty"`
	// Reason: why a rollback is requested (logged and reported).
	Reason string `json:"reason,omitempty"`
}

// applyResult is the updater's verdict.
type applyResult struct {
	Schema    int    `json:"schema"`
	State     string `json:"state"`
	Version   string `json:"version"`
	RolloutID string `json:"rollout_id"`
	Error     string `json:"error,omitempty"`
}

// trialRec: the running binary is on probation.
type trialRec struct {
	Version   string `json:"version"`
	RolloutID string `json:"rollout_id"`
}

// pendingReport is an UpdateStatus owed to the panel (sent after the next
// Hello), e.g. a rollback the updater performed.
type pendingReport struct {
	RolloutID string                `json:"rollout_id"`
	Version   string                `json:"version"`
	State     pb.UpdateStatus_State `json:"state"`
	Error     string                `json:"error"`
}

// updState is the agent's own record. Files of the exec-launcher era
// (current/previous/trial slots) load fine: unknown fields are dropped.
type updState struct {
	Schema     int            `json:"schema"`
	RolledBack []string       `json:"rolled_back,omitempty"`
	Report     *pendingReport `json:"report,omitempty"`
}

// updater owns the agent side of the update directory.
type updater struct {
	dir     string
	keys    []release.PublicKey
	version string // running version
	// unit: the updater's trigger unit file; "" = do not check (tests).
	unit        string
	selfCheck   time.Duration
	applyWait   time.Duration
	restartWait time.Duration
	poll        time.Duration

	mu sync.Mutex
	st updState
	// The update in progress (0 = none): its token and the stream it
	// belongs to. An update of a dead stream never blocks the next
	// stream's offer (it aborts on its own: its context is done).
	busyTok, busyGen, nextTok uint64
}

func newUpdater(stateDir, version string, keys []release.PublicKey) (*updater, error) {
	u := &updater{
		dir:         filepath.Join(stateDir, updateDirName),
		keys:        keys,
		version:     version,
		unit:        systemdInit.trigger,
		selfCheck:   defaultSelfCheck,
		applyWait:   defaultApplyWait,
		restartWait: defaultRestartWait,
		poll:        200 * time.Millisecond,
		st:          updState{Schema: stateSchema},
	}
	if err := os.MkdirAll(u.dir, 0o700); err != nil {
		return nil, fmt.Errorf("update dir: %w", err)
	}
	// The exec-launcher era staged executables in bin/ (never run again).
	if err := os.RemoveAll(filepath.Join(u.dir, "bin")); err != nil {
		slog.Warn("cannot remove the old staged binaries", "error", err)
	}
	if err := u.load(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *updater) path(name string) string { return filepath.Join(u.dir, name) }
func (u *updater) statePath() string       { return u.path(updateStateFile) }

func (u *updater) load() error {
	b, err := os.ReadFile(u.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update state: %w", err)
	}
	var st updState
	if err := json.Unmarshal(b, &st); err != nil || st.Schema != stateSchema {
		// Never let a damaged file stop the agent: set it aside.
		bad := u.statePath() + ".corrupt"
		slog.Error("update state unreadable; ignoring it", "error", err, "schema", st.Schema, "moved_to", bad)
		_ = os.Rename(u.statePath(), bad)
		return nil
	}
	st.Schema = stateSchema
	u.st = st
	return nil
}

func (u *updater) saveLocked() error {
	b, err := json.Marshal(&u.st)
	if err != nil {
		return err
	}
	return writeSecret(u.statePath(), b)
}

// updaterInstalled: is the privileged updater there to hand updates to?
func (u *updater) updaterInstalled() bool {
	if u.unit == "" {
		return true
	}
	_, err := os.Stat(u.unit)
	return err == nil
}

// boot runs at process start: it settles what the updater left behind
// (a rollback or a refused request becomes a report owed to the panel) and
// returns the probation record when THIS process is a freshly installed
// binary that has not passed its self-check yet.
func (u *updater) boot() (*trialRec, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	// A request no updater picked up and the download behind it are stale
	// (the updater removes the request before it acts on it; it holds the
	// staged file open while it copies it).
	stale := []string{u.path(requestName), u.path(stagedName)}
	if tmps, err := filepath.Glob(u.path(".download-*.tmp")); err == nil {
		stale = append(stale, tmps...) // an interrupted download
	}
	for _, p := range stale {
		if err := os.Remove(p); err == nil {
			slog.Warn("removed a stale update file", "file", filepath.Base(p))
		}
	}
	res, err := u.readResult()
	if err != nil {
		slog.Error("update result unreadable; ignoring it", "error", err)
		_ = os.Remove(u.path(resultName))
		return nil, nil
	}
	if res == nil {
		_ = os.Remove(u.path(confirmedName))
		return nil, nil
	}
	switch res.State {
	case resInstalled:
		if res.Version != u.version {
			// Not this binary (a reinstall replaced it, or the updater is
			// about to restart into it): nothing to judge here.
			return nil, nil
		}
		if c, _ := os.ReadFile(u.path(confirmedName)); string(c) == res.Version {
			return nil, nil // passed; the updater has not seen it yet
		}
		return &trialRec{Version: res.Version, RolloutID: res.RolloutID}, nil
	case resRolledBack:
		u.markRolledBackLocked(res.Version)
		u.st.Report = &pendingReport{RolloutID: res.RolloutID, Version: res.Version,
			State: pb.UpdateStatus_STATE_ROLLED_BACK, Error: truncate(res.Error, 512)}
	case resRejected, resRollbackFailed:
		// The previous process stopped before it could report it.
		u.st.Report = &pendingReport{RolloutID: res.RolloutID, Version: res.Version,
			State: pb.UpdateStatus_STATE_FAILED, Error: truncate(res.Error, 512)}
	}
	_ = os.Remove(u.path(resultName))
	_ = os.Remove(u.path(confirmedName))
	return nil, u.saveLocked()
}

func (u *updater) markRolledBackLocked(v string) {
	if v == "" || slices.Contains(u.st.RolledBack, v) {
		return
	}
	u.st.RolledBack = append(u.st.RolledBack, v)
	if len(u.st.RolledBack) > maxRolledBack {
		u.st.RolledBack = u.st.RolledBack[len(u.st.RolledBack)-maxRolledBack:]
	}
}

// parseApplyRequest decodes an apply request strictly (untrusted input to
// the privileged updater: unknown fields, trailing data, unknown kinds and
// oversized values are errors).
func parseApplyRequest(b []byte) (*applyRequest, error) {
	if len(b) > maxRequestSize {
		return nil, errors.New("apply request too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r applyRequest
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("apply request: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("apply request: trailing data")
	}
	switch {
	case r.Schema != requestSchema:
		return nil, fmt.Errorf("apply request: schema %d", r.Schema)
	case r.Kind != kindApply && r.Kind != kindRollback:
		return nil, fmt.Errorf("apply request: kind %q", r.Kind)
	case !release.ValidVersion(r.Version):
		return nil, fmt.Errorf("apply request: version %q", r.Version)
	case len(r.RolloutID) > 64 || len(r.Reason) > 512 || len(r.Signatures) > 8:
		return nil, errors.New("apply request: field out of range")
	}
	return &r, nil
}

// digest is the SHA-256 (hex) and length of at most limit+1 bytes of r.
func digest(r io.Reader, limit int64) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, limit+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readResult reads the updater's verdict (nil when there is none).
func (u *updater) readResult() (*applyResult, error) {
	b, err := readSmall(u.path(resultName), maxResultSize)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r applyResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func readSmall(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// rolledBack reports whether this node already rolled back from v.
func (u *updater) rolledBack(v string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Contains(u.st.RolledBack, v)
}

// tryBusy claims the update slot for stream gen: refused while an update
// of the same stream runs; one of an older (dead) stream is superseded.
func (u *updater) tryBusy(gen uint64) (uint64, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.busyTok != 0 && u.busyGen == gen {
		return 0, false
	}
	u.nextTok++
	u.busyTok, u.busyGen = u.nextTok, gen
	return u.busyTok, true
}

// setIdle releases the slot if tok still holds it.
func (u *updater) setIdle(tok uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.busyTok == tok {
		u.busyTok = 0
	}
}

// writeRequest hands a request to the updater: written atomically (the
// path unit fires on its appearance).
func (u *updater) writeRequest(r applyRequest) error {
	r.Schema = requestSchema
	b, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	return writeSecret(u.path(requestName), b)
}

// errApplyCanceled: the wait for the updater's verdict ended with the
// stream (the updater carries on; the next process settles its result).
var errApplyCanceled = errors.New("stream ended while the updater was working")

// requestApply stages the request and waits for the updater's verdict.
// done ends the wait early (the stream or the process is going away).
func (u *updater) requestApply(done <-chan struct{}, r applyRequest) (*applyResult, error) {
	_ = os.Remove(u.path(resultName))
	_ = os.Remove(u.path(confirmedName))
	r.Kind = kindApply
	if err := u.writeRequest(r); err != nil {
		return nil, fmt.Errorf("write the apply request: %w", err)
	}
	deadline := time.NewTimer(u.applyWait)
	defer deadline.Stop()
	tick := time.NewTicker(u.poll)
	defer tick.Stop()
	for {
		res, err := u.readResult()
		if err != nil {
			return nil, fmt.Errorf("updater result: %w", err)
		}
		if res != nil && res.Version == r.Version {
			return res, nil
		}
		select {
		case <-done:
			return nil, errApplyCanceled
		case <-deadline.C:
			// Withdraw the request if the updater never took it.
			if os.Remove(u.path(requestName)) == nil {
				return nil, errors.New("the updater did not pick up the request (is akari-agent-update.path enabled? run the panel's install command (重装命令) once)")
			}
			return nil, errors.New("the updater gave no verdict in time (journalctl -u akari-agent-update)")
		case <-tick.C:
		}
	}
}

// confirm ends the probation of the running binary: the updater watches
// for this marker.
func (u *updater) confirm(version string) error {
	return writeSecret(u.path(confirmedName), []byte(version))
}

// requestRollback: the running binary failed its self-check. The updater
// rolls back only a binary that is still on probation in ITS records.
func (u *updater) requestRollback(t trialRec, why string) error {
	return u.writeRequest(applyRequest{Kind: kindRollback, RolloutID: t.RolloutID, Version: t.Version,
		Reason: truncate(why, 512)})
}

// report returns the UpdateStatus owed to the panel, if any.
func (u *updater) report() *pendingReport {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Report == nil {
		return nil
	}
	r := *u.st.Report
	return &r
}

// clearReport drops r once delivered (unless a newer one replaced it).
func (u *updater) clearReport(r *pendingReport) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Report == nil || *u.st.Report != *r {
		return
	}
	u.st.Report = nil
	if err := u.saveLocked(); err != nil {
		slog.Warn("cannot persist the delivered update report", "error", err)
	}
}

// --- final counters across a restart ----------------------------------------

type finalsFile struct {
	Reports [][]byte `json:"reports"` // protobuf TrafficReport
}

// finalsStore persists the final-counter queue in the state directory.
// It is independent of the self-updater: a graceful stop (SIGTERM) and an
// update restart both use it.
type finalsStore struct{ dir string }

func (u *finalsStore) finalsPath() string { return filepath.Join(u.dir, finalsFileName) }

// save persists reports owed to the panel (before a restart).
func (u *finalsStore) save(reports []*pb.TrafficReport) error {
	var f finalsFile
	for _, r := range reports {
		b, err := proto.Marshal(r)
		if err != nil {
			return err
		}
		f.Reports = append(f.Reports, b)
	}
	b, err := json.Marshal(&f)
	if err != nil {
		return err
	}
	return writeSecret(u.finalsPath(), b)
}

// load returns the persisted reports (the file stays until
// drop: a crash before delivery keeps them).
func (u *finalsStore) load() []*pb.TrafficReport {
	b, err := os.ReadFile(u.finalsPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("cannot read persisted final counters", "error", err)
		}
		return nil
	}
	var f finalsFile
	if err := json.Unmarshal(b, &f); err != nil {
		slog.Error("persisted final counters unreadable; dropping them", "error", err)
		u.drop()
		return nil
	}
	var out []*pb.TrafficReport
	for _, raw := range f.Reports {
		var r pb.TrafficReport
		if proto.Unmarshal(raw, &r) == nil {
			out = append(out, &r)
		}
	}
	return out
}

func (u *finalsStore) drop() {
	if err := os.Remove(u.finalsPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("cannot remove persisted final counters", "error", err)
	}
}
