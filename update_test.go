package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"akari/agent/pb"
	"akari/agent/release"
)

// --- helpers ------------------------------------------------------------------

type relKey struct {
	priv ed25519.PrivateKey
	pub  release.PublicKey
}

func newRelKey(t *testing.T) relKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return relKey{priv, release.PublicKey{ID: release.KeyID(pub), Key: pub}}
}

func manifestFor(t *testing.T, version string, bin []byte, mod func(*release.Manifest)) []byte {
	t.Helper()
	sum := sha256.Sum256(bin)
	m := &release.Manifest{Schema: 1, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(bin)), MinPanelProtocol: 3,
		CreatedAt: "2026-10-02T00:00:00Z"}
	if mod != nil {
		mod(m)
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func offer(k relKey, manifest []byte) *pb.PanelDown {
	s := release.Sign(manifest, k.priv)
	return &pb.PanelDown{Msg: &pb.PanelDown_UpdateOffer{UpdateOffer: &pb.UpdateOffer{
		RolloutId: "r1", Manifest: manifest, PanelProtocol: 3,
		Signatures: []*pb.ManifestSignature{{KeyId: s.KeyID, Signature: s.Sig}}}}}
}

// execRecorder is a fake syscall.Exec.
type execRecorder struct {
	mu    sync.Mutex
	paths []string
	err   error // nil: "succeeds" (errExecuted)
}

func (e *execRecorder) exec(path string, argv, env []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.paths = append(e.paths, path)
	if e.err != nil {
		return e.err
	}
	launched := false
	for _, kv := range env {
		launched = launched || kv == envLaunched+"=1"
	}
	if !launched || argv[0] != path {
		return os.ErrInvalid
	}
	return errExecuted
}

func (e *execRecorder) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.paths...)
}

func testUpdater(t *testing.T, dir, version string, keys []release.PublicKey) (*updater, *execRecorder) {
	t.Helper()
	u, err := newUpdater(dir, version, keys)
	if err != nil {
		t.Fatal(err)
	}
	u.self = "/usr/local/bin/akari-agent"
	ex := &execRecorder{}
	u.exec = ex.exec
	return u, ex
}

// stage writes a binary into u's bin dir and returns its slot.
func stage(t *testing.T, u *updater, k relKey, version string, bin []byte) slot {
	t.Helper()
	mb := manifestFor(t, version, bin, nil)
	m, err := release.ParseManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	p := u.stagedPath(m)
	if err := os.WriteFile(p, bin, 0o700); err != nil {
		t.Fatal(err)
	}
	return slot{Version: version, Path: p, Manifest: mb, Signatures: []release.Signature{release.Sign(mb, k.priv)}}
}

func readState(t *testing.T, u *updater) updState {
	t.Helper()
	b, err := os.ReadFile(u.statePath())
	if err != nil {
		t.Fatal(err)
	}
	var st updState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// --- launcher / state machine ------------------------------------------------

func TestLaunchBootCounterRollsBackAfterMaxBoots(t *testing.T) {
	k := newRelKey(t)
	u, ex := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	next := stage(t, u, k, "v1.1.0", []byte("new agent"))
	if _, err := u.commit(next, "r1"); err != nil { // the switch counts boot 1
		t.Fatal(err)
	}
	if st := readState(t, u); st.Trial == nil || st.Trial.Boots != 1 || st.Previous != nil || st.Installed != u.self {
		t.Fatalf("after commit: %+v", st)
	}
	// The new binary crashes; systemd restarts the installed one each time.
	for boot := 2; boot <= u.maxBoots; boot++ {
		trial, err := u.launch(false)
		if err != errExecuted || trial != nil {
			t.Fatalf("boot %d: launch = %v, %v", boot, trial, err)
		}
		if st := readState(t, u); st.Trial.Boots != boot {
			t.Fatalf("boot counter %d, want %d", st.Trial.Boots, boot)
		}
	}
	trial, err := u.launch(false)
	if err != nil || trial != nil {
		t.Fatalf("launch after max boots = %v, %v (want: run the installed binary)", trial, err)
	}
	st := readState(t, u)
	if st.Current != nil || st.Trial != nil || len(st.RolledBack) != 1 || st.RolledBack[0] != "v1.1.0" {
		t.Fatalf("not rolled back: %+v", st)
	}
	if st.Report == nil || st.Report.State != pb.UpdateStatus_STATE_ROLLED_BACK || st.Report.RolloutID != "r1" {
		t.Fatalf("rollback not reported: %+v", st.Report)
	}
	if len(ex.calls()) != u.maxBoots-1 {
		t.Fatalf("exec calls %v", ex.calls())
	}
	if _, err := os.Stat(next.Path); !os.IsNotExist(err) {
		t.Fatal("rolled-back binary not garbage-collected")
	}
	if !u.rolledBack("v1.1.0") {
		t.Fatal("rolled-back version not remembered")
	}
}

func TestLaunchProbationAndConfirmedChain(t *testing.T) {
	k := newRelKey(t)
	dir := t.TempDir()
	u, _ := testUpdater(t, dir, "v1.0.0", []release.PublicKey{k.pub})
	b := stage(t, u, k, "v1.1.0", []byte("agent b"))
	if _, err := u.commit(b, "r1"); err != nil {
		t.Fatal(err)
	}
	// The exec'd new binary sees itself on probation.
	ub, exB := testUpdater(t, dir, "v1.1.0", []release.PublicKey{k.pub})
	ub.self = b.Path
	trial, err := ub.launch(true)
	if err != nil || trial == nil || trial.Version != "v1.1.0" || trial.RolloutID != "r1" {
		t.Fatalf("probation not detected: %+v %v", trial, err)
	}
	if err := ub.confirm(); err != nil {
		t.Fatal(err)
	}
	// A later update from the confirmed staged binary keeps it as previous.
	c := stage(t, ub, k, "v1.2.0", []byte("agent c"))
	if _, err := ub.commit(c, "r2"); err != nil {
		t.Fatal(err)
	}
	st := readState(t, ub)
	if st.Previous == nil || st.Previous.Path != b.Path || st.Current.Path != c.Path {
		t.Fatalf("chain: %+v", st)
	}
	// c fails its self-check: back to b (exec'd), not the installed binary.
	uc, exC := testUpdater(t, dir, "v1.2.0", []release.PublicKey{k.pub})
	uc.self = c.Path
	target, err := uc.rollbackTrial("self-check timeout")
	if err != nil || target != b.Path {
		t.Fatalf("rollback target %q %v", target, err)
	}
	_ = exB
	_ = exC
	// The fresh installed launcher now execs b (confirmed, no boot count).
	ui, exI := testUpdater(t, dir, "v1.0.0", []release.PublicKey{k.pub})
	if _, err := ui.launch(false); err != errExecuted {
		t.Fatalf("launcher did not exec the previous staged binary: %v", err)
	}
	if got := exI.calls(); len(got) != 1 || got[0] != b.Path {
		t.Fatalf("exec %v", got)
	}
	if st := readState(t, ui); st.Trial != nil || !contains(st.RolledBack, "v1.2.0") {
		t.Fatalf("state %+v", st)
	}
	// b, exec'd by the launcher, drops c's file.
	ub2, _ := testUpdater(t, dir, "v1.1.0", []release.PublicKey{k.pub})
	ub2.self = b.Path
	if trial, err := ub2.launch(true); err != nil || trial != nil {
		t.Fatalf("launched b: %v %v", trial, err)
	}
	if _, err := os.Stat(c.Path); !os.IsNotExist(err) {
		t.Fatal("rolled-back binary left in bin/")
	}
	if _, err := os.Stat(b.Path); err != nil {
		t.Fatal("running binary removed")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestLaunchInstalledNewerWinsAndCorruptStagedRollsBack(t *testing.T) {
	k := newRelKey(t)
	dir := t.TempDir()
	u, _ := testUpdater(t, dir, "v1.0.0", []release.PublicKey{k.pub})
	b := stage(t, u, k, "v1.1.0", []byte("agent b"))
	if _, err := u.commit(b, "r1"); err != nil {
		t.Fatal(err)
	}
	// Package upgrade of the installed binary past the staged one.
	u2, ex2 := testUpdater(t, dir, "v1.2.0", []release.PublicKey{k.pub})
	if trial, err := u2.launch(false); err != nil || trial != nil || len(ex2.calls()) != 0 {
		t.Fatalf("staged older binary exec'd: %v %v %v", trial, err, ex2.calls())
	}
	if st := readState(t, u2); st.Current != nil || len(st.RolledBack) != 0 {
		t.Fatalf("state %+v", st)
	}

	// Corrupted staged file: never exec'd, rolled back.
	dir2 := t.TempDir()
	u3, ex3 := testUpdater(t, dir2, "v1.0.0", []release.PublicKey{k.pub})
	c := stage(t, u3, k, "v1.1.0", []byte("agent c"))
	if _, err := u3.commit(c, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Path, []byte("agent X"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := u3.launch(false); err != nil || len(ex3.calls()) != 0 {
		t.Fatalf("corrupt staged binary: %v %v", err, ex3.calls())
	}
	if st := readState(t, u3); st.Current != nil || st.Report == nil {
		t.Fatalf("state %+v", st)
	}
	// A damaged state file is set aside, never fatal.
	if err := os.WriteFile(u3.statePath(), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newUpdater(dir2, "v1.0.0", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(u3.statePath() + ".corrupt"); err != nil {
		t.Fatal("corrupt state not set aside")
	}
}

func TestFinalsPersistRoundTrip(t *testing.T) {
	u, _ := testUpdater(t, t.TempDir(), "v1.0.0", nil)
	in := []*pb.TrafficReport{{SessionId: "s1", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 5, DownBytes: 7}}}}
	if err := (&finalsStore{dir: u.dir}).save(in); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat((&finalsStore{dir: u.dir}).finalsPath()); st.Mode().Perm() != 0o600 {
		t.Fatal("finals file not 0600")
	}
	fs := &finalsStore{dir: u.dir}
	out := fs.load()
	if len(out) != 1 || out[0].SessionId != "s1" || out[0].Users[0].DownBytes != 7 {
		t.Fatalf("round trip %v", out)
	}
	fs.drop()
	if fs.load() != nil {
		t.Fatal("finals not dropped")
	}
}

// --- session: offer, download, switch, self-check ---------------------------

type updPanel struct {
	pb.UnimplementedAgentChannelServer
	streams  atomic.Int32
	onStream func(n int32, s pb.AgentChannel_OpenChannelServer) error
	artifact []byte
	fetches  atomic.Int32
	// cutFirst: the first fetch delivers half and fails (resume path).
	cutFirst bool
}

func (f *updPanel) OpenChannel(s pb.AgentChannel_OpenChannelServer) error {
	return f.onStream(f.streams.Add(1), s)
}

func (f *updPanel) FetchArtifact(req *pb.FetchArtifactRequest, s pb.AgentChannel_FetchArtifactServer) error {
	n := f.fetches.Add(1)
	sum := sha256.Sum256(f.artifact)
	if req.Sha256 != hex.EncodeToString(sum[:]) {
		return status.Error(codes.NotFound, "unknown artifact")
	}
	data := f.artifact[req.Offset:]
	if n == 1 && f.cutFirst {
		_ = s.Send(&pb.ArtifactChunk{Data: data[:len(data)/2]})
		return status.Error(codes.Unavailable, "cut")
	}
	for len(data) > 0 {
		c := min(len(data), 3)
		if err := s.Send(&pb.ArtifactChunk{Data: data[:c]}); err != nil {
			return err
		}
		data = data[c:]
	}
	return nil
}

func startUpdPanel(t *testing.T, f *updPanel) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterAgentChannelServer(srv, f)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

// collectStatuses drains a stream, forwarding UpdateStatus messages.
func collectStatuses(s pb.AgentChannel_OpenChannelServer, out chan<- *pb.UpdateStatus) {
	for {
		m, err := s.Recv()
		if err != nil {
			return
		}
		if us, ok := m.Msg.(*pb.AgentUp_UpdateStatus); ok {
			out <- us.UpdateStatus
		}
	}
}

func waitStatus(t *testing.T, ch <-chan *pb.UpdateStatus, want pb.UpdateStatus_State) *pb.UpdateStatus {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case s := <-ch:
			if s.State == want {
				return s
			}
		case <-deadline:
			t.Fatalf("no %v status", want)
			return nil
		}
	}
}

func runUpdAgent(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestUpdateOfferDownloadVerifySwitch(t *testing.T) {
	k := newRelKey(t)
	bin := []byte("the new agent binary, version 1.1.0")
	statuses := make(chan *pb.UpdateStatus, 32)
	f := &updPanel{artifact: bin, cutFirst: true}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		_ = s.Send(offer(k, manifestFor(t, "v1.1.0", bin, nil)))
		collectStatuses(s, statuses)
		return nil
	}
	addr := startUpdPanel(t, f)
	a := testAgent(t, addr)
	a.agentVersion = "v1.0.0"
	a.fetchBackoff = 10 * time.Millisecond
	u, ex := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	a.upd = u
	// Final counters owed when the switch happens must be persisted.
	a.finals.add(&pb.TrafficReport{SessionId: "old", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 1}}})
	runUpdAgent(t, a)

	waitStatus(t, statuses, pb.UpdateStatus_STATE_DOWNLOADING)
	st := waitStatus(t, statuses, pb.UpdateStatus_STATE_RESTARTING)
	if st.Version != "v1.1.0" || st.RolloutId != "r1" {
		t.Fatalf("status %+v", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(ex.calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	calls := ex.calls()
	if len(calls) != 1 {
		t.Fatalf("exec calls %v", calls)
	}
	got, err := os.ReadFile(calls[0])
	if err != nil || string(got) != string(bin) {
		t.Fatalf("staged binary %q %v", got, err)
	}
	if fi, _ := os.Stat(calls[0]); fi.Mode().Perm() != 0o700 {
		t.Fatalf("staged binary mode %v", fi.Mode().Perm())
	}
	if f.fetches.Load() != 2 {
		t.Fatalf("expected a resumed download, fetches=%d", f.fetches.Load())
	}
	s := readState(t, u)
	if s.Current == nil || s.Current.Version != "v1.1.0" || s.Trial == nil || s.Trial.Boots != 1 || s.Trial.RolloutID != "r1" {
		t.Fatalf("state %+v", s)
	}
	fin := (&finalsStore{dir: u.dir}).load()
	if len(fin) != 1 || fin[0].SessionId != "old" {
		t.Fatalf("final counters not persisted before the switch: %v", fin)
	}
	if entries, _ := filepath.Glob(filepath.Join(u.binDir(), ".download-*")); len(entries) != 0 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestUpdateOfferRejections(t *testing.T) {
	k, other := newRelKey(t), newRelKey(t)
	bin := []byte("payload")
	good := manifestFor(t, "v1.1.0", bin, nil)
	tampered := offer(k, good)
	tampered.GetUpdateOffer().Manifest = manifestFor(t, "v1.1.1", bin, nil)
	cases := map[string]*pb.PanelDown{
		"unpinned key": offer(other, good),
		"tampered":     tampered,
		"downgrade":    offer(k, manifestFor(t, "v0.9.0", bin, nil)),
		"same version": offer(k, manifestFor(t, "v1.0.0", bin, nil)),
		"foreign arch": offer(k, manifestFor(t, "v1.1.0", bin, func(m *release.Manifest) { m.Arch = "s390x" })),
		"newer panel":  offer(k, manifestFor(t, "v1.1.0", bin, func(m *release.Manifest) { m.MinPanelProtocol = 9 })),
		"rolled back":  offer(k, manifestFor(t, "v1.0.5", bin, nil)),
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			statuses := make(chan *pb.UpdateStatus, 8)
			f := &updPanel{artifact: bin}
			f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
				recvHello(t, s)
				_ = s.Send(o)
				collectStatuses(s, statuses)
				return nil
			}
			a := testAgent(t, startUpdPanel(t, f))
			a.agentVersion = "v1.0.0"
			u, ex := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
			u.st.RolledBack = []string{"v1.0.5"}
			a.upd = u
			runUpdAgent(t, a)
			waitStatus(t, statuses, pb.UpdateStatus_STATE_REJECTED)
			time.Sleep(50 * time.Millisecond)
			if f.fetches.Load() != 0 || len(ex.calls()) != 0 {
				t.Fatalf("rejected offer still fetched/exec'd")
			}
		})
	}
}

func TestUpdateDigestMismatchFails(t *testing.T) {
	k := newRelKey(t)
	statuses := make(chan *pb.UpdateStatus, 8)
	signedFor := []byte("what the release key signed")
	f := &updPanel{artifact: []byte("what a compromised panel serves")}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		// The panel serves its own bytes under the signed digest.
		m := manifestFor(t, "v1.1.0", signedFor, nil)
		_ = s.Send(offer(k, m))
		collectStatuses(s, statuses)
		return nil
	}
	a := testAgent(t, startUpdPanel(t, f))
	a.agentVersion = "v1.0.0"
	a.fetchBackoff = time.Millisecond
	u, ex := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	a.upd = u
	runUpdAgent(t, a)
	waitStatus(t, statuses, pb.UpdateStatus_STATE_FAILED)
	if len(ex.calls()) != 0 {
		t.Fatal("exec'd an unverified binary")
	}
	if entries, _ := os.ReadDir(u.binDir()); len(entries) != 0 {
		t.Fatalf("files left in bin/: %v", entries)
	}
}

// A binary on probation that never gets an ok-acked apply rolls itself back
// to the previous one; one that does confirms and stays.
func TestTrialSelfCheck(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout rolls back", true: "ok apply confirms"}[apply], func(t *testing.T) {
			k := newRelKey(t)
			dir := t.TempDir()
			u0, _ := testUpdater(t, dir, "v1.0.0", []release.PublicKey{k.pub})
			next := stage(t, u0, k, "v1.1.0", []byte("agent b"))
			if _, err := u0.commit(next, "r1"); err != nil {
				t.Fatal(err)
			}
			u, ex := testUpdater(t, dir, "v1.1.0", []release.PublicKey{k.pub})
			u.self = next.Path
			rec, err := u.launch(true)
			if err != nil || rec == nil {
				t.Fatalf("launch %v %v", rec, err)
			}
			u.selfCheck = 300 * time.Millisecond
			statuses := make(chan *pb.UpdateStatus, 8)
			inb, users := testSnapshot(freePort(t))
			f := &updPanel{}
			f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
				recvHello(t, s)
				if apply {
					_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
						ConfigVersion: 1, UserVersion: 1, InboundsJson: inb, Users: users}}})
				}
				collectStatuses(s, statuses)
				return nil
			}
			a := testAgent(t, startUpdPanel(t, f))
			a.agentVersion = "v1.1.0"
			a.upd = u
			a.trial = newTrialState(rec)
			var exits atomic.Int32
			a.exit = func(int) { exits.Add(1) }
			runUpdAgent(t, a)
			if apply {
				waitStatus(t, statuses, pb.UpdateStatus_STATE_CONFIRMED)
				time.Sleep(600 * time.Millisecond)
				if len(ex.calls()) != 0 {
					t.Fatalf("confirmed binary rolled back: %v", ex.calls())
				}
				if st := readState(t, u); st.Trial != nil || st.Current.Version != "v1.1.0" {
					t.Fatalf("state %+v", st)
				}
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			for len(ex.calls()) == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if c := ex.calls(); len(c) != 1 || c[0] != u.st.Installed {
				t.Fatalf("rollback exec %v (installed %q)", c, u.st.Installed)
			}
			st := readState(t, u)
			if st.Current != nil || !contains(st.RolledBack, "v1.1.0") || st.Report == nil ||
				st.Report.State != pb.UpdateStatus_STATE_ROLLED_BACK {
				t.Fatalf("state %+v", st)
			}
			if exits.Load() != 0 {
				t.Fatal("exited instead of exec")
			}
		})
	}
}

// The binary that runs after a rollback reports it after its Hello.
func TestPendingReportDeliveredAfterHello(t *testing.T) {
	statuses := make(chan *pb.UpdateStatus, 8)
	f := &updPanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		collectStatuses(s, statuses)
		return nil
	}
	a := testAgent(t, startUpdPanel(t, f))
	u, _ := testUpdater(t, t.TempDir(), "v1.0.0", nil)
	u.st.Report = &pendingReport{RolloutID: "r9", Version: "v1.1.0",
		State: pb.UpdateStatus_STATE_ROLLED_BACK, Error: "crashed"}
	if err := u.saveLocked(); err != nil {
		t.Fatal(err)
	}
	a.upd = u
	runUpdAgent(t, a)
	st := waitStatus(t, statuses, pb.UpdateStatus_STATE_ROLLED_BACK)
	if st.RolloutId != "r9" || st.Error != "crashed" {
		t.Fatalf("%+v", st)
	}
	deadline := time.Now().Add(3 * time.Second)
	for u.report() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if u.report() != nil || readState(t, u).Report != nil {
		t.Fatal("delivered report not cleared")
	}
}

// An update of a dead stream never blocks the next stream's offer.
func TestBusySlotPerStream(t *testing.T) {
	u, _ := testUpdater(t, t.TempDir(), "v1.0.0", nil)
	t1, ok := u.tryBusy(1)
	if !ok {
		t.Fatal("first claim refused")
	}
	if _, ok := u.tryBusy(1); ok {
		t.Fatal("second update on the same stream allowed")
	}
	t2, ok := u.tryBusy(2)
	if !ok {
		t.Fatal("new stream blocked by a dead stream's update")
	}
	u.setIdle(t1) // the old one finishing must not release the new claim
	if _, ok := u.tryBusy(2); ok {
		t.Fatal("stale release freed the current claim")
	}
	u.setIdle(t2)
	if _, ok := u.tryBusy(2); !ok {
		t.Fatal("slot not released")
	}
}
