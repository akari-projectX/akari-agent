package main

// Signed self-update (M6), node side: the staged-binary store, the launcher
// that runs the newest staged binary, the boot counter and the rollback.
//
// Layout (<state dir>/update, 0700; files 0600, binaries 0700):
//
//	state.json   which staged binary to run (current), the one before it
//	             (previous), the probation record (trial), versions this
//	             node rolled back from, and a pending report for the panel
//	finals.json  final traffic counters persisted across a restart
//	bin/akari-agent-<version>-<sha256[:12]>   staged binaries
//
// The installed binary (systemd ExecStart, read-only /usr/local/bin) is the
// LAUNCHER: started fresh, it execs the current staged binary when that is
// newer than itself. Every exec into a binary on probation counts a boot;
// after maxBoots boots without a passed self-check (a connected stream and
// an ok-acked apply) the launcher marks the version failed and falls back to
// the previous binary (or itself). A staged binary that runs but cannot pass
// its self-check within the timeout rolls itself back the same way.

import (
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
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
	"akari/agent/release"
)

const (
	updateDirName   = "update"
	updateStateFile = "state.json"
	finalsFileName  = "finals.json"
	// envLaunched marks a process started by exec from another agent
	// process (launcher, update switch or rollback): it never execs again
	// at startup, so a bad state file cannot cause an exec loop.
	envLaunched = "AKARI_AGENT_LAUNCHED"

	defaultSelfCheck = 5 * time.Minute
	defaultMaxBoots  = 3
	maxRolledBack    = 32
	stateSchema      = 1
)

// errExecuted is returned by a fake exec (tests) in place of not returning.
var errExecuted = errors.New("process image replaced")

// slot is a staged, verified binary.
type slot struct {
	Version    string              `json:"version"`
	Path       string              `json:"path"`
	Manifest   []byte              `json:"manifest"` // signed bytes, verbatim
	Signatures []release.Signature `json:"signatures"`
}

// trialRec: the current binary is on probation.
type trialRec struct {
	Version   string    `json:"version"`
	RolloutID string    `json:"rollout_id"`
	Boots     int       `json:"boots"`
	Started   time.Time `json:"started"`
}

// pendingReport is an UpdateStatus owed to the panel (sent after the next
// Hello), e.g. a rollback the launcher performed.
type pendingReport struct {
	RolloutID string                `json:"rollout_id"`
	Version   string                `json:"version"`
	State     pb.UpdateStatus_State `json:"state"`
	Error     string                `json:"error"`
}

type updState struct {
	Schema int `json:"schema"`
	// Installed: path of the binary systemd starts (the launcher).
	Installed  string         `json:"installed,omitempty"`
	Current    *slot          `json:"current,omitempty"`
	Previous   *slot          `json:"previous,omitempty"`
	Trial      *trialRec      `json:"trial,omitempty"`
	RolledBack []string       `json:"rolled_back,omitempty"`
	Report     *pendingReport `json:"report,omitempty"`
}

// updater owns the update directory.
type updater struct {
	dir       string
	keys      []release.PublicKey
	version   string // running version
	self      string // running executable
	maxBoots  int
	selfCheck time.Duration
	// exec replaces the process image (syscall.Exec); returns only on
	// failure (tests: errExecuted).
	exec func(path string, argv, env []string) error
	now  func() time.Time

	mu sync.Mutex
	st updState
	// The update in progress (0 = none): its token and the stream it
	// belongs to. An update of a dead stream never blocks the next
	// stream's offer (it aborts on its own: its context is done).
	busyTok, busyGen, nextTok uint64
}

func newUpdater(stateDir, version string, keys []release.PublicKey) (*updater, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("own executable: %w", err)
	}
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	u := &updater{
		dir:       filepath.Join(stateDir, updateDirName),
		keys:      keys,
		version:   version,
		self:      self,
		maxBoots:  defaultMaxBoots,
		selfCheck: defaultSelfCheck,
		exec:      syscall.Exec,
		now:       time.Now,
		st:        updState{Schema: stateSchema},
	}
	if err := os.MkdirAll(u.binDir(), 0o700); err != nil {
		return nil, fmt.Errorf("update dir: %w", err)
	}
	if err := u.load(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *updater) binDir() string    { return filepath.Join(u.dir, "bin") }
func (u *updater) statePath() string { return filepath.Join(u.dir, updateStateFile) }

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
		// Never let a damaged file stop the agent: set it aside and run
		// the installed binary.
		bad := u.statePath() + ".corrupt"
		slog.Error("update state unreadable; ignoring it", "error", err, "schema", st.Schema, "moved_to", bad)
		_ = os.Rename(u.statePath(), bad)
		return nil
	}
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

// launch runs at process start, before anything else. A fresh start (the
// installed binary, not exec'd by another agent process) execs the current
// staged binary when it is newer than itself — counting a boot when that
// binary is on probation and rolling back once it used up maxBoots. It
// returns the probation record when THIS process is the binary on
// probation; nil otherwise.
func (u *updater) launch(launched bool) (*trialRec, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !launched {
		u.st.Installed = u.self
	}
	for range 4 {
		cur := u.st.Current
		if cur == nil {
			return nil, u.saveGC()
		}
		if launched {
			if cur.Path == u.self && u.st.Trial != nil && u.st.Trial.Version == cur.Version && cur.Version == u.version {
				t := *u.st.Trial
				return &t, nil
			}
			return nil, nil
		}
		// Fresh start: this is the installed binary.
		if c, err := release.CompareVersions(cur.Version, u.version); err == nil && c <= 0 {
			// The installed binary was upgraded past the staged one
			// (package update): it wins; staged binaries are dropped.
			slog.Info("installed agent is not older than the staged one; dropping staged binaries",
				"installed", u.version, "staged", cur.Version)
			u.st.Current, u.st.Previous, u.st.Trial = nil, nil, nil
			continue
		}
		if t := u.st.Trial; t != nil && t.Version == cur.Version {
			t.Boots++
			if t.Boots > u.maxBoots {
				u.rollbackLocked(fmt.Sprintf("did not pass its self-check in %d starts", u.maxBoots))
				continue
			}
		}
		if err := verifySlot(cur); err != nil {
			u.rollbackLocked("staged binary failed verification: " + err.Error())
			continue
		}
		if err := u.saveLocked(); err != nil {
			// Without a recorded boot the counter could not stop a crash
			// loop: run the installed binary instead.
			slog.Error("cannot record the boot of the staged agent; running the installed one", "error", err)
			return nil, nil
		}
		slog.Info("starting staged agent", "version", cur.Version, "path", cur.Path)
		err := u.exec(cur.Path, argvFor(cur.Path), launchedEnv())
		if errors.Is(err, errExecuted) {
			return nil, err
		}
		u.rollbackLocked(fmt.Sprintf("exec failed: %v", err))
	}
	return nil, u.saveGC()
}

// rollbackLocked: the current binary failed. Mark its version (never
// accepted again), owe the panel a report, and fall back to the previous
// binary (nil = the installed one).
func (u *updater) rollbackLocked(why string) {
	cur := u.st.Current
	if cur == nil {
		return
	}
	rid := ""
	if t := u.st.Trial; t != nil && t.Version == cur.Version {
		rid = t.RolloutID
	}
	slog.Error("rolling back agent update", "version", cur.Version, "reason", why)
	if !slices.Contains(u.st.RolledBack, cur.Version) {
		u.st.RolledBack = append(u.st.RolledBack, cur.Version)
		if len(u.st.RolledBack) > maxRolledBack {
			u.st.RolledBack = u.st.RolledBack[len(u.st.RolledBack)-maxRolledBack:]
		}
	}
	u.st.Report = &pendingReport{RolloutID: rid, Version: cur.Version,
		State: pb.UpdateStatus_STATE_ROLLED_BACK, Error: truncate(why, 512)}
	u.st.Current, u.st.Previous, u.st.Trial = u.st.Previous, nil, nil
}

// saveGC persists the state and removes staged files nothing refers to.
func (u *updater) saveGC() error {
	if err := u.saveLocked(); err != nil {
		return err
	}
	u.gcLocked()
	return nil
}

func (u *updater) gcLocked() {
	keep := map[string]bool{}
	for _, s := range []*slot{u.st.Current, u.st.Previous} {
		if s != nil {
			keep[s.Path] = true
		}
	}
	entries, err := os.ReadDir(u.binDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(u.binDir(), e.Name())
		if keep[p] || (u.busyTok != 0 && strings.HasPrefix(e.Name(), ".download-")) {
			continue
		}
		if err := os.Remove(p); err == nil {
			slog.Info("removed unused staged agent file", "path", p)
		}
	}
}

// verifySlot re-checks a staged binary before it is exec'd: the manifest
// is well-formed and names this version, and the file matches its size and
// SHA-256 (disk corruption, tampering by anything without the agent's own
// privileges is out of reach anyway: the directory is 0700). The signature
// was verified by the binary that accepted the offer (a launcher built
// before a key rotation may not pin the newer key, so it is not re-checked
// here).
func verifySlot(s *slot) error {
	m, err := release.ParseManifest(s.Manifest)
	if err != nil {
		return err
	}
	if m.Version != s.Version {
		return fmt.Errorf("manifest version %s != slot version %s", m.Version, s.Version)
	}
	sum, size, err := fileDigest(s.Path, m.Size)
	if err != nil {
		return err
	}
	if size != m.Size || sum != m.SHA256 {
		return fmt.Errorf("%s does not match its manifest", s.Path)
	}
	return nil
}

func fileDigest(path string, limit int64) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func argvFor(path string) []string {
	argv := append([]string{path}, os.Args[1:]...)
	return argv
}

func launchedEnv() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, envLaunched+"=") {
			env = append(env, kv)
		}
	}
	return append(env, envLaunched+"=1")
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

// stagedPath is where a verified download of m is kept.
func (u *updater) stagedPath(m *release.Manifest) string {
	return filepath.Join(u.binDir(), fmt.Sprintf("akari-agent-%s-%s", m.Version, m.SHA256[:12]))
}

// commit records new as the current binary, on probation (its first boot
// counted), with what runs now as the previous one. It returns an undo for
// a failed exec.
func (u *updater) commit(next slot, rolloutID string) (undo func(), err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	before := u.st
	if u.st.Installed == "" {
		u.st.Installed = u.self
	}
	var prev *slot
	if c := u.st.Current; c != nil && c.Path == u.self {
		prev = c
	}
	u.st.Previous = prev
	u.st.Current = &next
	u.st.Trial = &trialRec{Version: next.Version, RolloutID: rolloutID, Boots: 1, Started: u.now().UTC()}
	if err := u.saveLocked(); err != nil {
		u.st = before
		return nil, err
	}
	u.gcLocked()
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.st = before
		if err := u.saveLocked(); err != nil {
			slog.Error("cannot restore the update state after a failed switch", "error", err)
		}
	}, nil
}

// confirm ends the probation of the running binary.
func (u *updater) confirm() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Trial == nil {
		return nil
	}
	u.st.Trial = nil
	return u.saveLocked()
}

// rollbackTrial: the running binary failed its self-check. Returns the
// binary to exec instead.
func (u *updater) rollbackTrial(why string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rollbackLocked(why)
	target := u.st.Installed
	if u.st.Current != nil {
		target = u.st.Current.Path
	}
	if target == "" {
		return "", errors.New("no binary to roll back to")
	}
	return target, u.saveLocked()
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

func (u *updater) finalsPath() string { return filepath.Join(u.dir, finalsFileName) }

// saveFinals persists reports owed to the panel (before a restart).
func (u *updater) saveFinals(reports []*pb.TrafficReport) error {
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

// loadFinals returns the persisted reports (the file stays until
// dropFinals: a crash before delivery keeps them).
func (u *updater) loadFinals() []*pb.TrafficReport {
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
		u.dropFinals()
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

func (u *updater) dropFinals() {
	if err := os.Remove(u.finalsPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("cannot remove persisted final counters", "error", err)
	}
}
