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
	"strings"
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

func testUpdater(t *testing.T, dir, version string, keys []release.PublicKey) *updater {
	t.Helper()
	u, err := newUpdater(dir, version, keys)
	if err != nil {
		t.Fatal(err)
	}
	u.unit = "" // tests: no systemd unit to look for
	u.poll = 5 * time.Millisecond
	return u
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

// writeResult plays the updater's part: a verdict in the agent's directory.
func writeResult(t *testing.T, u *updater, r applyResult) {
	t.Helper()
	r.Schema = requestSchema
	b, _ := json.Marshal(&r)
	if err := os.WriteFile(u.path(resultName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeUpdater answers the next apply request with verdict (from the
// request it saw).
func fakeUpdater(t *testing.T, u *updater, verdict func(*applyRequest) applyResult) <-chan *applyRequest {
	t.Helper()
	seen := make(chan *applyRequest, 1)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			b, err := os.ReadFile(u.path(requestName))
			if err != nil {
				continue
			}
			_ = os.Remove(u.path(requestName))
			r, err := parseApplyRequest(b)
			if err != nil {
				t.Errorf("agent wrote a request the updater refuses: %v", err)
				return
			}
			seen <- r
			res := verdict(r)
			res.Schema = requestSchema
			rb, _ := json.Marshal(&res)
			_ = os.WriteFile(u.path(resultName), rb, 0o600)
			return
		}
	}()
	return seen
}

// --- boot: what the updater left behind -----------------------------------

func TestBootSettlesTheUpdaterResult(t *testing.T) {
	t.Run("rolled back: reported, never accepted again", func(t *testing.T) {
		dir := t.TempDir()
		u := testUpdater(t, dir, "v1.0.0", nil)
		writeResult(t, u, applyResult{State: resRolledBack, Version: "v1.1.0", RolloutID: "r1", Error: "crashed"})
		if trial, err := u.boot(); err != nil || trial != nil {
			t.Fatalf("boot %v %v", trial, err)
		}
		st := readState(t, u)
		if !contains(st.RolledBack, "v1.1.0") || st.Report == nil || st.Report.State != pb.UpdateStatus_STATE_ROLLED_BACK ||
			st.Report.RolloutID != "r1" || st.Report.Error != "crashed" {
			t.Fatalf("state %+v", st)
		}
		if _, err := os.Stat(u.path(resultName)); !os.IsNotExist(err) {
			t.Fatal("settled result kept")
		}
		if !u.rolledBack("v1.1.0") {
			t.Fatal("rolled-back version not remembered")
		}
	})
	t.Run("rejected while the agent was gone: FAILED owed", func(t *testing.T) {
		u := testUpdater(t, t.TempDir(), "v1.0.0", nil)
		writeResult(t, u, applyResult{State: resRejected, Version: "v1.1.0", RolloutID: "r2", Error: "bad"})
		if _, err := u.boot(); err != nil {
			t.Fatal(err)
		}
		if r := u.report(); r == nil || r.State != pb.UpdateStatus_STATE_FAILED || r.RolloutID != "r2" {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("installed and this is the binary: on probation", func(t *testing.T) {
		u := testUpdater(t, t.TempDir(), "v1.1.0", nil)
		writeResult(t, u, applyResult{State: resInstalled, Version: "v1.1.0", RolloutID: "r3"})
		trial, err := u.boot()
		if err != nil || trial == nil || trial.Version != "v1.1.0" || trial.RolloutID != "r3" {
			t.Fatalf("boot %+v %v", trial, err)
		}
		// Already confirmed (restart before the updater saw it): not again.
		if err := u.confirm("v1.1.0"); err != nil {
			t.Fatal(err)
		}
		if trial, _ := u.boot(); trial != nil {
			t.Fatalf("confirmed binary on probation again: %+v", trial)
		}
	})
	t.Run("installed for another binary: left alone", func(t *testing.T) {
		u := testUpdater(t, t.TempDir(), "v1.0.0", nil)
		writeResult(t, u, applyResult{State: resInstalled, Version: "v1.1.0"})
		if trial, _ := u.boot(); trial != nil {
			t.Fatal("probation for another version")
		}
		if _, err := os.Stat(u.path(resultName)); err != nil {
			t.Fatal("the updater's in-flight result removed")
		}
	})
	t.Run("stale request and download removed; exec-era state loads", func(t *testing.T) {
		dir := t.TempDir()
		upd := filepath.Join(dir, updateDirName)
		if err := os.MkdirAll(filepath.Join(upd, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		legacy := `{"schema":1,"installed":"/usr/local/bin/akari-agent","current":{"version":"v0.4.0","path":"x"},` +
			`"trial":{"version":"v0.4.0","boots":2},"rolled_back":["v0.3.9"]}`
		for name, body := range map[string]string{updateStateFile: legacy, requestName: "{}", stagedName: "bin",
			"bin/akari-agent-v0.4.0-abc": "old", ".download-1.tmp": "partial"} {
			if err := os.WriteFile(filepath.Join(upd, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		u := testUpdater(t, dir, "v1.0.0", nil)
		if _, err := u.boot(); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{requestName, stagedName, "bin", ".download-1.tmp"} {
			if _, err := os.Stat(u.path(n)); !os.IsNotExist(err) {
				t.Fatalf("%s kept", n)
			}
		}
		if !u.rolledBack("v0.3.9") {
			t.Fatal("legacy rolled_back list lost")
		}
	})
	t.Run("corrupt state set aside", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, updateDirName), 0o700)
		_ = os.WriteFile(filepath.Join(dir, updateDirName, updateStateFile), []byte("{"), 0o600)
		u := testUpdater(t, dir, "v1.0.0", nil)
		if _, err := os.Stat(u.statePath() + ".corrupt"); err != nil {
			t.Fatal("corrupt state not set aside")
		}
	})
}

func TestParseApplyRequestIsStrict(t *testing.T) {
	good := `{"schema":1,"kind":"apply","rollout_id":"r","version":"v1.2.3","panel_protocol":3}`
	if _, err := parseApplyRequest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"unknown field": `{"schema":1,"kind":"apply","version":"v1.2.3","path":"/etc/shadow"}`,
		"trailing":      good + `{}`,
		"schema":        `{"schema":2,"kind":"apply","version":"v1.2.3"}`,
		"kind":          `{"schema":1,"kind":"exec","version":"v1.2.3"}`,
		"version":       `{"schema":1,"kind":"apply","version":"../x"}`,
		"long reason":   `{"schema":1,"kind":"rollback","version":"v1.2.3","reason":"` + strings.Repeat("x", 600) + `"}`,
		"too large":     strings.Repeat(" ", maxRequestSize+1) + good,
	} {
		if _, err := parseApplyRequest([]byte(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFinalsPersistRoundTrip(t *testing.T) {
	u := testUpdater(t, t.TempDir(), "v1.0.0", nil)
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

func TestUpdateOfferDownloadVerifyHandOver(t *testing.T) {
	k := newRelKey(t)
	bin := []byte("the new agent binary, version 1.1.0")
	statuses := make(chan *pb.UpdateStatus, 32)
	f := &updPanel{artifact: bin, cutFirst: true}
	mb := manifestFor(t, "v1.1.0", bin, nil)
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		_ = s.Send(offer(k, mb))
		collectStatuses(s, statuses)
		return nil
	}
	addr := startUpdPanel(t, f)
	a := testAgent(t, addr)
	a.agentVersion = "v1.0.0"
	a.fetchBackoff = 10 * time.Millisecond
	u := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	a.upd = u
	var exits atomic.Int32
	a.exit = func(int) { exits.Add(1) }
	// Final counters owed when the switch happens must be persisted.
	a.finals.add(&pb.TrafficReport{SessionId: "old", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 1}}})
	type stagedFile struct {
		b    []byte
		mode os.FileMode
	}
	stagedCh := make(chan stagedFile, 1)
	seen := fakeUpdater(t, u, func(r *applyRequest) applyResult {
		var sf stagedFile
		sf.b, _ = os.ReadFile(u.path(stagedName))
		if fi, err := os.Stat(u.path(stagedName)); err == nil {
			sf.mode = fi.Mode().Perm()
		}
		stagedCh <- sf
		return applyResult{State: resInstalled, Version: r.Version, RolloutID: r.RolloutID}
	})
	runUpdAgent(t, a)

	waitStatus(t, statuses, pb.UpdateStatus_STATE_DOWNLOADING)
	st := waitStatus(t, statuses, pb.UpdateStatus_STATE_RESTARTING)
	if st.Version != "v1.1.0" || st.RolloutId != "r1" {
		t.Fatalf("status %+v", st)
	}
	var r *applyRequest
	select {
	case r = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("no apply request")
	}
	if r.Kind != kindApply || r.Version != "v1.1.0" || r.RolloutID != "r1" || r.PanelProtocol != 3 ||
		string(r.Manifest) != string(mb) || len(r.Signatures) != 1 || r.Signatures[0].KeyID != k.pub.ID {
		t.Fatalf("request %+v", r)
	}
	if sf := <-stagedCh; string(sf.b) != string(bin) || sf.mode != 0o600 {
		t.Fatalf("staged %q mode %v (never executable)", sf.b, sf.mode)
	}
	if f.fetches.Load() != 2 {
		t.Fatalf("expected a resumed download, fetches=%d", f.fetches.Load())
	}
	fin := (&finalsStore{dir: u.dir}).load()
	if len(fin) != 1 || fin[0].SessionId != "old" {
		t.Fatalf("final counters not persisted before the switch: %v", fin)
	}
	if entries, _ := filepath.Glob(filepath.Join(u.dir, ".download-*")); len(entries) != 0 {
		t.Fatalf("temp files left: %v", entries)
	}
	// "installed": the agent waits for the updater's restart, and exits
	// when none comes (systemd then starts the new binary).
	if exits.Load() != 0 {
		t.Fatal("exited before the restart wait")
	}
}

func TestUpdateInstalledButNoRestartExits(t *testing.T) {
	k := newRelKey(t)
	bin := []byte("v1.1.0 binary")
	f := &updPanel{artifact: bin}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		_ = s.Send(offer(k, manifestFor(t, "v1.1.0", bin, nil)))
		collectStatuses(s, make(chan *pb.UpdateStatus, 32))
		return nil
	}
	a := testAgent(t, startUpdPanel(t, f))
	a.agentVersion = "v1.0.0"
	u := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	u.restartWait = 50 * time.Millisecond
	a.upd = u
	exited := make(chan int, 1)
	a.exit = func(c int) { exited <- c }
	fakeUpdater(t, u, func(r *applyRequest) applyResult {
		return applyResult{State: resInstalled, Version: r.Version, RolloutID: r.RolloutID}
	})
	runUpdAgent(t, a)
	select {
	case c := <-exited:
		if c == 0 {
			t.Fatal("exit code 0 (systemd Restart=always restarts either way, but 0 hides the cause)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent kept running the old binary after the install")
	}
}

// The updater's refusal (or no updater at all) undoes the switch: FAILED
// with the reason, a fresh Hello, nothing staged left.
func TestUpdateRefusedOrNoUpdater(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		verdict    func(*applyRequest) applyResult
	}{
		{"refused", "the updater refused v1.1.0: signature", func(r *applyRequest) applyResult {
			return applyResult{State: resRejected, Version: r.Version, RolloutID: r.RolloutID, Error: "signature"}
		}},
		{"no updater", "did not pick up the request", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newRelKey(t)
			bin := []byte("v1.1.0 binary")
			statuses := make(chan *pb.UpdateStatus, 32)
			var hellos atomic.Int32
			f := &updPanel{artifact: bin}
			f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
				recvHello(t, s)
				_ = s.Send(offer(k, manifestFor(t, "v1.1.0", bin, nil)))
				for {
					m, err := s.Recv()
					if err != nil {
						return nil
					}
					switch x := m.Msg.(type) {
					case *pb.AgentUp_Hello:
						hellos.Add(1)
					case *pb.AgentUp_UpdateStatus:
						statuses <- x.UpdateStatus
					}
				}
			}
			a := testAgent(t, startUpdPanel(t, f))
			a.agentVersion = "v1.0.0"
			u := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
			u.applyWait = 200 * time.Millisecond
			a.upd = u
			if tc.verdict != nil {
				fakeUpdater(t, u, tc.verdict)
			}
			runUpdAgent(t, a)
			st := waitStatus(t, statuses, pb.UpdateStatus_STATE_FAILED)
			if !strings.Contains(st.Error, tc.want) {
				t.Fatalf("error %q, want %q", st.Error, tc.want)
			}
			deadline := time.Now().Add(3 * time.Second)
			for hellos.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if hellos.Load() == 0 {
				t.Fatal("no Hello after the undone switch")
			}
			for _, n := range []string{stagedName, requestName, resultName} {
				if _, err := os.Stat(u.path(n)); !os.IsNotExist(err) {
					t.Fatalf("%s left behind", n)
				}
			}
		})
	}
}

func TestUpdateOfferRejections(t *testing.T) {
	k, other := newRelKey(t), newRelKey(t)
	bin := []byte("payload")
	good := manifestFor(t, "v1.1.0", bin, nil)
	tampered := offer(k, good)
	tampered.GetUpdateOffer().Manifest = manifestFor(t, "v1.1.1", bin, nil)
	cases := map[string]struct {
		o    *pb.PanelDown
		want string
	}{
		"unpinned key":    {offer(other, good), "no valid signature"},
		"tampered":        {tampered, "no valid signature"},
		"downgrade":       {offer(k, manifestFor(t, "v0.9.0", bin, nil)), "downgrade"},
		"same version":    {offer(k, manifestFor(t, "v1.0.0", bin, nil)), "already running"},
		"foreign arch":    {offer(k, manifestFor(t, "v1.1.0", bin, func(m *release.Manifest) { m.Arch = "s390x" })), "s390x"},
		"newer panel":     {offer(k, manifestFor(t, "v1.1.0", bin, func(m *release.Manifest) { m.MinPanelProtocol = 9 })), "panel protocol"},
		"rolled back":     {offer(k, manifestFor(t, "v1.0.5", bin, nil)), "rolled back"},
		"updater missing": {offer(k, good), "updater unit missing"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			statuses := make(chan *pb.UpdateStatus, 8)
			f := &updPanel{artifact: bin}
			f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
				recvHello(t, s)
				_ = s.Send(tc.o)
				collectStatuses(s, statuses)
				return nil
			}
			a := testAgent(t, startUpdPanel(t, f))
			a.agentVersion = "v1.0.0"
			u := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
			u.st.RolledBack = []string{"v1.0.5"}
			if name == "updater missing" {
				u.unit = filepath.Join(t.TempDir(), "akari-agent-update.path")
			}
			a.upd = u
			runUpdAgent(t, a)
			st := waitStatus(t, statuses, pb.UpdateStatus_STATE_REJECTED)
			if !strings.Contains(st.Error, tc.want) {
				t.Fatalf("error %q, want %q", st.Error, tc.want)
			}
			time.Sleep(50 * time.Millisecond)
			if f.fetches.Load() != 0 {
				t.Fatalf("rejected offer still fetched")
			}
			if _, err := os.Stat(u.path(requestName)); !os.IsNotExist(err) {
				t.Fatal("rejected offer reached the updater")
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
	u := testUpdater(t, t.TempDir(), "v1.0.0", []release.PublicKey{k.pub})
	a.upd = u
	runUpdAgent(t, a)
	waitStatus(t, statuses, pb.UpdateStatus_STATE_FAILED)
	entries, _ := os.ReadDir(u.dir)
	for _, e := range entries {
		if e.Name() != updateStateFile {
			t.Fatalf("file left in update/: %s", e.Name())
		}
	}
}

// A binary on probation that never gets an ok-acked apply asks the updater
// to roll it back; one that does records its confirmation for the updater.
func TestTrialSelfCheck(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout requests a rollback", true: "ok apply confirms"}[apply], func(t *testing.T) {
			k := newRelKey(t)
			u := testUpdater(t, t.TempDir(), "v1.1.0", []release.PublicKey{k.pub})
			writeResult(t, u, applyResult{State: resInstalled, Version: "v1.1.0", RolloutID: "r1"})
			rec, err := u.boot()
			if err != nil || rec == nil {
				t.Fatalf("boot %v %v", rec, err)
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
				if c, _ := os.ReadFile(u.path(confirmedName)); string(c) != "v1.1.0" {
					t.Fatalf("confirmation marker %q", c)
				}
				if _, err := os.Stat(u.path(requestName)); !os.IsNotExist(err) {
					t.Fatal("confirmed binary asked for a rollback")
				}
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			var b []byte
			for time.Now().Before(deadline) {
				if b, err = os.ReadFile(u.path(requestName)); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			r, err := parseApplyRequest(b)
			if err != nil || r.Kind != kindRollback || r.Version != "v1.1.0" || r.RolloutID != "r1" ||
				!strings.Contains(r.Reason, "no connected, acknowledged apply") {
				t.Fatalf("rollback request %+v %v", r, err)
			}
			if _, err := os.Stat(u.path(confirmedName)); !os.IsNotExist(err) {
				t.Fatal("failed binary confirmed")
			}
			if exits.Load() != 0 {
				t.Fatal("exited (the updater restarts it)")
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
	u := testUpdater(t, t.TempDir(), "v1.0.0", nil)
	writeResult(t, u, applyResult{State: resRolledBack, Version: "v1.1.0", RolloutID: "r9", Error: "crashed"})
	if _, err := u.boot(); err != nil {
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
	u := testUpdater(t, t.TempDir(), "v1.0.0", nil)
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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
