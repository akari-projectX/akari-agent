package main

// Signed self-update (M6), session side: UpdateOffer handling, the artifact
// download over the existing mTLS connection (AgentChannel.FetchArtifact),
// the switch to the new binary and the probation (self-check) of a freshly
// started one. See update.go for the on-disk side and the launcher.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"akari/agent/pb"
	"akari/agent/release"
)

const (
	fetchAttempts = 6
	// How long the switch waits for the RESTARTING status (and anything
	// queued before it) to reach the transport.
	switchFlushWait = 2 * time.Second
)

// trialState: this process runs a binary on probation.
type trialState struct {
	rec       trialRec
	confirmed chan struct{}
	once      sync.Once
}

func newTrialState(rec *trialRec) *trialState {
	if rec == nil {
		return nil
	}
	return &trialState{rec: *rec, confirmed: make(chan struct{})}
}

func (t *trialState) isConfirmed() bool {
	select {
	case <-t.confirmed:
		return true
	default:
		return false
	}
}

func updateStatus(rolloutID, version string, st pb.UpdateStatus_State, err error) *pb.AgentUp {
	us := &pb.UpdateStatus{RolloutId: rolloutID, Version: version, State: st}
	if err != nil {
		us.Error = truncate(err.Error(), 512)
	}
	return &pb.AgentUp{Msg: &pb.AgentUp_UpdateStatus{UpdateStatus: us}}
}

// onUpdateOffer judges an offer (signature under a pinned key, manifest,
// platform, version policy) and starts the download. Caller holds applyMu.
func (a *Agent) onUpdateOffer(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, o *pb.UpdateOffer) error {
	reject := func(version string, err error) error {
		slog.Warn("update offer rejected", "version", version, "error", err)
		return send(updateStatus(o.GetRolloutId(), version, pb.UpdateStatus_STATE_REJECTED, err))
	}
	if a.upd == nil {
		return reject("", errors.New("self-update unavailable on this node (no writable update directory)"))
	}
	sigs := make([]release.Signature, 0, len(o.GetSignatures()))
	for _, s := range o.GetSignatures() {
		sigs = append(sigs, release.Signature{KeyID: s.GetKeyId(), Sig: s.GetSignature()})
	}
	m, perr := release.ParseManifest(o.GetManifest())
	version := ""
	if perr == nil {
		version = m.Version
	}
	keyID, err := release.Verify(o.GetManifest(), sigs, a.upd.keys)
	if err != nil {
		return reject(version, err)
	}
	if perr != nil {
		return reject(version, perr)
	}
	policy := release.Policy{Running: a.agentVersion, OS: runtime.GOOS, Arch: runtime.GOARCH,
		PanelProtocol: o.GetPanelProtocol(), RolledBack: a.upd.rolledBack}
	if err := policy.Check(m); err != nil {
		return reject(version, err)
	}
	if t := a.trial; t != nil && !t.isConfirmed() {
		return reject(version, errors.New("the running update has not passed its self-check yet"))
	}
	tok, ok := a.upd.tryBusy(gen)
	if !ok {
		slog.Info("update offer ignored: an update is already in progress", "version", version)
		return nil
	}
	conn := a.connFor(gen)
	if conn == nil {
		a.upd.setIdle(tok)
		return errStreamGone
	}
	slog.Info("update offer accepted", "version", m.Version, "key", keyID, "rollout", o.GetRolloutId())
	off := acceptedOffer{rolloutID: o.GetRolloutId(), m: m, raw: o.GetManifest(), sigs: sigs}
	go a.runUpdate(ctx, gen, send, conn, off, tok)
	return nil
}

type acceptedOffer struct {
	rolloutID string
	m         *release.Manifest
	raw       []byte
	sigs      []release.Signature
}

// connFor returns stream gen's connection, nil if it is no longer current.
func (a *Agent) connFor(gen uint64) grpc.ClientConnInterface {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.streamGen != gen {
		return nil
	}
	return a.curConn
}

// runUpdate downloads, verifies and stages the offered binary, then
// switches to it. Bound to the offering stream: if it dies, nothing is
// switched (the panel offers again on the next stream).
func (a *Agent) runUpdate(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, conn grpc.ClientConnInterface, off acceptedOffer, tok uint64) {
	defer a.upd.setIdle(tok)
	m := off.m
	fail := func(err error) {
		slog.Error("agent update failed", "version", m.Version, "error", err)
		if ctx.Err() == nil {
			_ = send(updateStatus(off.rolloutID, m.Version, pb.UpdateStatus_STATE_FAILED, err))
		}
	}
	_ = send(updateStatus(off.rolloutID, m.Version, pb.UpdateStatus_STATE_DOWNLOADING, nil))
	tmp, err := a.download(ctx, conn, m)
	if err != nil {
		fail(err)
		return
	}
	path := a.upd.stagedPath(m)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		fail(fmt.Errorf("stage: %w", err))
		return
	}
	syncDir(a.upd.binDir())
	next := slot{Version: m.Version, Path: path, Manifest: off.raw, Signatures: off.sigs}
	if err := verifySlot(&next); err != nil {
		fail(err)
		return
	}
	slog.Info("agent update verified and staged", "version", m.Version, "path", path)

	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if ctx.Err() != nil {
		return // stream gone: the next one gets the offer again
	}
	if err := a.switchLocked(gen, send, next, off.rolloutID); err != nil {
		fail(err)
	}
}

// download fetches m's artifact into a temp file in the update directory,
// resuming after transient errors, and checks size and SHA-256.
func (a *Agent) download(ctx context.Context, conn grpc.ClientConnInterface, m *release.Manifest) (string, error) {
	f, err := os.CreateTemp(a.upd.binDir(), ".download-*.tmp")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	var n int64
	backoff := a.fetchBackoff
	for attempt := 1; ; attempt++ {
		err := a.fetchOnce(ctx, conn, m, f, h, &n)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if attempt >= fetchAttempts || permanentFetchError(err) {
			return "", fmt.Errorf("download: %w", err)
		}
		slog.Warn("artifact download interrupted; resuming", "error", err, "offset", n, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	if n != m.Size {
		return "", fmt.Errorf("download: got %d bytes, manifest says %d", n, m.Size)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != m.SHA256 {
		return "", fmt.Errorf("download: sha256 %s does not match the signed manifest", sum)
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Chmod(0o700); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return f.Name(), nil
}

var errTooLarge = errors.New("artifact larger than its manifest")

func (a *Agent) fetchOnce(ctx context.Context, conn grpc.ClientConnInterface, m *release.Manifest, f *os.File, h hash.Hash, n *int64) error {
	stream, err := pb.NewAgentChannelClient(conn).FetchArtifact(ctx,
		&pb.FetchArtifactRequest{Sha256: m.SHA256, Offset: uint64(*n)})
	if err != nil {
		return err
	}
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		d := chunk.GetData()
		if *n+int64(len(d)) > m.Size {
			return errTooLarge
		}
		if _, err := f.Write(d); err != nil {
			return &permanentError{err}
		}
		h.Write(d)
		*n += int64(len(d))
	}
}

type permanentError struct{ error }

func permanentFetchError(err error) bool {
	var p *permanentError
	if errors.Is(err, errTooLarge) || errors.As(err, &p) {
		return true
	}
	switch status.Code(err) {
	case codes.NotFound, codes.InvalidArgument, codes.Unauthenticated, codes.PermissionDenied, codes.Unimplemented:
		return true
	}
	return false
}

// stopForRestartLocked stops xray and persists every final counter report
// still owed (the next process resends them; accounting is idempotent).
// Caller holds applyMu.
func (a *Agent) stopForRestartLocked() {
	a.finals.add(a.core.Teardown())
	a.setVersions(0, 0)
	a.setDirty(false)
	a.persistFinalsLocked("restart")
}

// switchLocked restarts into the staged binary: final counters flushed
// (stream) and persisted (disk), state committed with the new binary on
// probation, then the process image is replaced. Only returns on failure
// (after undoing the switch and re-announcing the now empty state).
// Caller holds applyMu.
func (a *Agent) switchLocked(gen uint64, send func(*pb.AgentUp) error, next slot, rolloutID string) error {
	slog.Info("switching to the new agent", "version", next.Version)
	a.stopForRestartLocked()
	a.finals.flush(gen, send)
	_ = send(updateStatus(rolloutID, next.Version, pb.UpdateStatus_STATE_RESTARTING, nil))
	a.flushStream(gen, switchFlushWait)
	undo, err := a.upd.commit(next, rolloutID)
	if err == nil {
		err = a.upd.exec(next.Path, argvFor(next.Path), launchedEnv())
		if errors.Is(err, errExecuted) {
			return nil
		}
		undo()
	}
	// Still this binary, xray stopped: claim nothing so the panel resends
	// the desired state.
	if serr := send(a.helloLocked()); serr == nil {
		a.finals.flush(gen, send)
	}
	return fmt.Errorf("switch to %s: %w", next.Version, err)
}

// flushStream waits until everything queued on stream gen so far was handed
// to the transport (or the timeout).
func (a *Agent) flushStream(gen uint64, timeout time.Duration) {
	a.streamMu.Lock()
	flush := a.curFlush
	cur := a.streamGen
	a.streamMu.Unlock()
	if flush != nil && cur == gen {
		flush(timeout)
	}
}

// sendPendingReport delivers an UpdateStatus the update state owes the
// panel (e.g. a launcher rollback) on a fresh stream. Caller holds applyMu.
func (a *Agent) sendPendingReportLocked(gen uint64, send func(*pb.AgentUp) error) {
	if a.upd == nil {
		return
	}
	r := a.upd.report()
	if r == nil {
		return
	}
	var err error
	if r.Error != "" {
		err = errors.New(r.Error)
	}
	if send(updateStatus(r.RolloutID, r.Version, r.State, err)) != nil {
		return
	}
	go func() {
		a.flushStream(gen, switchFlushWait)
		if cur, s := a.current(); cur == gen && s != nil {
			a.upd.clearReport(r)
		}
	}()
}

// confirmTrialLocked: the binary on probation is connected and its apply
// was acked ok — it passed its self-check. Caller holds applyMu.
func (a *Agent) confirmTrialLocked(send func(*pb.AgentUp) error) {
	t := a.trial
	if t == nil || t.isConfirmed() {
		return
	}
	t.once.Do(func() { close(t.confirmed) })
	if err := a.upd.confirm(); err != nil {
		slog.Error("cannot persist the passed self-check", "error", err)
	}
	slog.Info("agent update passed its self-check", "version", t.rec.Version)
	_ = send(updateStatus(t.rec.RolloutID, t.rec.Version, pb.UpdateStatus_STATE_CONFIRMED, nil))
}

// trialLoop rolls the binary on probation back unless it passes its
// self-check within the timeout.
func (a *Agent) trialLoop(ctx context.Context) {
	t := a.trial
	timer := time.NewTimer(a.upd.selfCheck)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.confirmed:
		return
	case <-timer.C:
	}
	a.rollbackTrial(fmt.Sprintf("no connected, acknowledged apply within %s of starting", a.upd.selfCheck))
}

// rollbackTrial replaces this process with the previous binary.
func (a *Agent) rollbackTrial(why string) {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if a.trial.isConfirmed() {
		return
	}
	a.stopForRestartLocked()
	target, err := a.upd.rollbackTrial(why)
	if err == nil {
		err = a.upd.exec(target, argvFor(target), launchedEnv())
		if errors.Is(err, errExecuted) {
			return
		}
	}
	// Let the service manager restart the installed binary (its launcher
	// sees the rollback in the state file).
	slog.Error("rollback exec failed; exiting for a restart", "error", err)
	a.exit(1)
}
