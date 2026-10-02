//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"akari/agent/release"
)

// updaterEnv is a node in a temp dir: the agent's state dir, the updater's
// own state, and the installed binary.
type updaterEnv struct {
	t        *testing.T
	k        relKey
	agentDir string // <state>/update
	p        *applier
	clock    time.Time
	nRestart atomic.Int32 // systemd's NRestarts
	restarts atomic.Int32 // restart() calls
	// onRestart plays the new agent (after the install) or the old one.
	onRestart func(n int32)
}

func newUpdaterEnv(t *testing.T) *updaterEnv {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "var/lib/private/akari-agent")
	e := &updaterEnv{t: t, k: newRelKey(t), agentDir: filepath.Join(state, updateDirName),
		clock: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	for _, d := range []string{e.agentDir, filepath.Join(root, "usr/local/bin")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "usr/local/bin/akari-agent")
	if err := os.WriteFile(target, []byte("installed v1.0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := newApplier(state, filepath.Join(root, "var/lib/akari-agent-update"), target, "akari-agent.service",
		[]release.PublicKey{e.k.pub})
	p.version = "v1.0.0"
	p.goos, p.goarch = "linux", "amd64"
	p.selfCheck, p.grace, p.poll = 10*time.Second, 5*time.Second, time.Second
	p.now = func() time.Time { return e.clock }
	p.sleep = func(d time.Duration) { e.clock = e.clock.Add(d) }
	p.restart = func() error {
		n := e.restarts.Add(1)
		if e.onRestart != nil {
			e.onRestart(n)
		}
		return nil
	}
	p.restarts = func() (int, error) { return int(e.nRestart.Load()), nil }
	e.p = p
	return e
}

// stage plays the agent: staged binary + apply request.
func (e *updaterEnv) stage(version string, bin []byte, mod func(*applyRequest)) {
	e.t.Helper()
	mb := manifestFor(e.t, version, bin, func(m *release.Manifest) { m.OS, m.Arch = "linux", "amd64" })
	if err := os.WriteFile(filepath.Join(e.agentDir, stagedName), bin, 0o600); err != nil {
		e.t.Fatal(err)
	}
	r := applyRequest{Schema: requestSchema, Kind: kindApply, RolloutID: "r1", Version: version, PanelProtocol: 3,
		Manifest: mb, Signatures: []release.Signature{release.Sign(mb, e.k.priv)}}
	if mod != nil {
		mod(&r)
	}
	e.writeRequest(r)
}

func (e *updaterEnv) writeRequest(r applyRequest) {
	e.t.Helper()
	b, _ := json.Marshal(&r)
	if err := os.WriteFile(filepath.Join(e.agentDir, requestName), b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *updaterEnv) result() applyResult {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.agentDir, resultName))
	if err != nil {
		e.t.Fatalf("no result: %v", err)
	}
	var r applyResult
	if err := json.Unmarshal(b, &r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *updaterEnv) installed() string {
	b, _ := os.ReadFile(e.p.target)
	return string(b)
}

func (e *updaterEnv) rootState() rootState { return e.p.load() }

func (e *updaterEnv) confirm(v string) {
	if err := os.WriteFile(filepath.Join(e.agentDir, confirmedName), []byte(v), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func TestApplyInstallsVerifiedCopyAndConfirms(t *testing.T) {
	e := newUpdaterEnv(t)
	bin := []byte("new agent v1.1.0")
	e.stage("v1.1.0", bin, nil)
	e.onRestart = func(int32) {
		// The new binary runs and is on probation.
		if e.installed() != string(bin) {
			t.Error("restarted before the new binary was in place")
		}
		if r := e.result(); r.State != resInstalled || r.Version != "v1.1.0" {
			t.Errorf("result before the restart %+v", r)
		}
		if st := e.rootState(); st.Trial == nil || st.Trial.Version != "v1.1.0" || st.Trial.Previous != "v1.0.0" {
			t.Errorf("probation not recorded before the restart: %+v", st.Trial)
		}
		e.confirm("v1.1.0")
	}
	if err := e.p.run(); err != nil {
		t.Fatal(err)
	}
	if e.installed() != string(bin) {
		t.Fatalf("installed %q", e.installed())
	}
	if prev, _ := os.ReadFile(e.p.target + ".prev"); string(prev) != "installed v1.0.0" {
		t.Fatalf("previous binary not kept: %q", prev)
	}
	if fi, _ := os.Stat(e.p.target); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if r := e.result(); r.State != resConfirmed || r.RolloutID != "r1" {
		t.Fatalf("result %+v", r)
	}
	if st := e.rootState(); st.Trial != nil {
		t.Fatalf("probation kept %+v", st)
	}
	for _, n := range []string{requestName, stagedName, confirmedName} {
		if _, err := os.Stat(filepath.Join(e.agentDir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s left", n)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.p.target), ".*")); len(left) != 0 {
		t.Fatalf("temp files next to the target: %v", left)
	}
	if e.restarts.Load() != 1 {
		t.Fatalf("restarts %d", e.restarts.Load())
	}
}

func TestApplyRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		agent      func(e *updaterEnv) func(int32)
	}{
		{"crash loop", "stopped 3 times", func(e *updaterEnv) func(int32) {
			return func(n int32) {
				if n == 1 { // the new binary dies on every start: systemd restarts it
					e.p.restarts = func() (int, error) { return int(e.nRestart.Add(1)), nil }
				}
			}
		}},
		{"self-check timeout", "no connected, acknowledged apply", func(e *updaterEnv) func(int32) {
			return func(int32) {}
		}},
		{"agent asks", "self-check failed: no ack", func(e *updaterEnv) func(int32) {
			return func(n int32) {
				if n == 1 {
					e.writeRequest(applyRequest{Schema: requestSchema, Kind: kindRollback, RolloutID: "r1",
						Version: "v1.1.0", Reason: "no ack"})
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newUpdaterEnv(t)
			e.stage("v1.1.0", []byte("broken v1.1.0"), nil)
			e.onRestart = tc.agent(e)
			if err := e.p.run(); err != nil {
				t.Fatal(err)
			}
			if e.installed() != "installed v1.0.0" {
				t.Fatalf("not rolled back: %q", e.installed())
			}
			r := e.result()
			if r.State != resRolledBack || r.Version != "v1.1.0" || r.RolloutID != "r1" || !strings.Contains(r.Error, tc.want) {
				t.Fatalf("result %+v, want %q", r, tc.want)
			}
			if st := e.rootState(); st.Trial != nil || !contains(st.RolledBack, "v1.1.0") {
				t.Fatalf("root state %+v", st)
			}
			if e.restarts.Load() != 2 {
				t.Fatalf("restarts %d (install + rollback)", e.restarts.Load())
			}
			// Never again, whatever the agent's own records say.
			e.stage("v1.1.0", []byte("broken v1.1.0"), nil)
			if err := e.p.run(); err != nil {
				t.Fatal(err)
			}
			if r := e.result(); r.State != resRejected || !strings.Contains(r.Error, "rolled back") {
				t.Fatalf("rolled-back version accepted again: %+v", r)
			}
		})
	}
}

func TestApplyRefusesBadRequests(t *testing.T) {
	other := newRelKey(t)
	cases := []struct {
		name, want string
		setup      func(e *updaterEnv)
	}{
		{"unpinned key", "no valid signature", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("x"), func(r *applyRequest) {
				r.Signatures = []release.Signature{release.Sign(r.Manifest, other.priv)}
			})
		}},
		{"tampered manifest", "no valid signature", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("x"), func(r *applyRequest) {
				r.Manifest = manifestFor(t, "v1.1.0", []byte("y"), func(m *release.Manifest) { m.OS, m.Arch = "linux", "amd64" })
			})
		}},
		{"request names another version", "request names", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("x"), func(r *applyRequest) { r.Version = "v1.2.0" })
		}},
		{"downgrade", "downgrade", func(e *updaterEnv) { e.stage("v0.9.0", []byte("x"), nil) }},
		{"same version", "already running", func(e *updaterEnv) { e.stage("v1.0.0", []byte("x"), nil) }},
		{"foreign platform", "linux/arm64", func(e *updaterEnv) {
			e.p.goarch = "arm64"
			e.stage("v1.1.0", []byte("x"), nil)
		}},
		{"rolled back here", "rolled back", func(e *updaterEnv) {
			st := e.rootState()
			st.RolledBack = []string{"v1.1.0"}
			if err := os.MkdirAll(e.p.rootDir, 0o700); err != nil {
				t.Fatal(err)
			}
			_ = e.p.save(&st)
			e.stage("v1.1.0", []byte("x"), nil)
		}},
		{"staged bytes differ", "does not match the signed manifest", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("signed"), nil)
			_ = os.WriteFile(filepath.Join(e.agentDir, stagedName), []byte("evil!!"), 0o600)
		}},
		{"staged size differs", "the signed manifest says", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("signed"), nil)
			_ = os.WriteFile(filepath.Join(e.agentDir, stagedName), []byte("longer evil"), 0o600)
		}},
		{"staged symlink", "staged binary", func(e *updaterEnv) {
			bin := []byte("the real thing")
			e.stage("v1.1.0", bin, nil)
			real := filepath.Join(t.TempDir(), "real")
			_ = os.WriteFile(real, bin, 0o600)
			_ = os.Remove(filepath.Join(e.agentDir, stagedName))
			_ = os.Symlink(real, filepath.Join(e.agentDir, stagedName))
		}},
		{"staged hard link", "links", func(e *updaterEnv) {
			bin := []byte("the real thing")
			e.stage("v1.1.0", bin, nil)
			_ = os.Link(filepath.Join(e.agentDir, stagedName), filepath.Join(e.agentDir, "other"))
		}},
		{"staged fifo", "not a regular file", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("x"), nil)
			_ = os.Remove(filepath.Join(e.agentDir, stagedName))
			if err := syscall.Mkfifo(filepath.Join(e.agentDir, stagedName), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"staged directory", "not a regular file", func(e *updaterEnv) {
			e.stage("v1.1.0", []byte("x"), nil)
			_ = os.Remove(filepath.Join(e.agentDir, stagedName))
			_ = os.Mkdir(filepath.Join(e.agentDir, stagedName), 0o700)
		}},
		{"probation pending", "still on probation", func(e *updaterEnv) {
			st := rootState{Schema: stateSchema, Trial: &rootTrial{Version: "v1.0.0"}}
			_ = os.MkdirAll(e.p.rootDir, 0o700)
			_ = e.p.save(&st)
			e.stage("v1.1.0", []byte("x"), nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newUpdaterEnv(t)
			tc.setup(e)
			done := make(chan error, 1)
			go func() { done <- e.p.run() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("updater blocked")
			}
			if r := e.result(); r.State != resRejected || !strings.Contains(r.Error, tc.want) {
				t.Fatalf("result %+v, want %q", r, tc.want)
			}
			if e.installed() != "installed v1.0.0" || e.restarts.Load() != 0 {
				t.Fatal("refused update touched the node")
			}
			if _, err := os.Stat(filepath.Join(e.agentDir, requestName)); !os.IsNotExist(err) {
				t.Fatal("request not consumed")
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.p.target), ".*")); len(left) != 0 {
				t.Fatalf("temp files next to the target: %v", left)
			}
		})
	}
}

// What the unprivileged agent can plant must never make the updater follow
// it: symlinked directories or request files are errors (and the request is
// consumed, so the path unit does not loop).
func TestApplyRefusesPlantedLinks(t *testing.T) {
	t.Run("update dir is a symlink", func(t *testing.T) {
		e := newUpdaterEnv(t)
		elsewhere := t.TempDir()
		_ = os.RemoveAll(e.agentDir)
		_ = os.Symlink(elsewhere, e.agentDir)
		_ = os.WriteFile(filepath.Join(elsewhere, requestName), []byte("{}"), 0o600)
		if err := e.p.run(); err == nil {
			t.Fatal("followed a symlinked update dir")
		}
		if _, err := os.Stat(filepath.Join(elsewhere, requestName)); err != nil {
			t.Fatal("touched the symlink target")
		}
	})
	t.Run("request is a symlink", func(t *testing.T) {
		e := newUpdaterEnv(t)
		real := filepath.Join(t.TempDir(), "req")
		_ = os.WriteFile(real, []byte("{}"), 0o600)
		_ = os.Symlink(real, filepath.Join(e.agentDir, requestName))
		if err := e.p.run(); err == nil || !errors.Is(err, syscall.ELOOP) {
			t.Fatalf("err %v", err)
		}
		if _, err := os.Lstat(filepath.Join(e.agentDir, requestName)); !os.IsNotExist(err) {
			t.Fatal("planted request link not consumed")
		}
		if _, err := os.Stat(real); err != nil {
			t.Fatal("symlink target removed")
		}
	})
	t.Run("result name is a symlink", func(t *testing.T) {
		e := newUpdaterEnv(t)
		victim := filepath.Join(t.TempDir(), "victim")
		_ = os.WriteFile(victim, []byte("keep"), 0o600)
		_ = os.Symlink(victim, filepath.Join(e.agentDir, resultName))
		e.stage("v0.1.0", []byte("x"), nil) // refused: a result gets written
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatal("wrote through a planted symlink")
		}
		if r := e.result(); r.State != resRejected {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("garbage request", func(t *testing.T) {
		e := newUpdaterEnv(t)
		_ = os.WriteFile(filepath.Join(e.agentDir, requestName), []byte(`{"schema":1,"kind":"apply","path":"/etc"}`), 0o600)
		if err := e.p.run(); err == nil {
			t.Fatal("garbage accepted")
		}
		if _, err := os.Stat(filepath.Join(e.agentDir, requestName)); !os.IsNotExist(err) {
			t.Fatal("garbage request not consumed")
		}
	})
}

func TestApplyProbationBookkeeping(t *testing.T) {
	t.Run("confirmed while nobody watched", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.p.version = "v1.1.0" // the binary on probation is the one installed
		_ = os.MkdirAll(e.p.rootDir, 0o700)
		_ = e.p.save(&rootState{Schema: stateSchema, Trial: &rootTrial{Version: "v1.1.0", RolloutID: "r7"}})
		e.confirm("v1.1.0")
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if st := e.rootState(); st.Trial != nil {
			t.Fatal("probation kept")
		}
		if r := e.result(); r.State != resConfirmed || r.RolloutID != "r7" {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("stale probation dropped", func(t *testing.T) {
		e := newUpdaterEnv(t)
		_ = os.MkdirAll(e.p.rootDir, 0o700)
		_ = e.p.save(&rootState{Schema: stateSchema, Trial: &rootTrial{Version: "v1.1.0"}})
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if st := e.rootState(); st.Trial != nil {
			t.Fatal("stale probation kept (the installed binary is not on probation)")
		}
	})
	t.Run("rollback request after a reboot", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.p.version = "v1.1.0"
		_ = os.WriteFile(e.p.target+".prev", []byte("installed v1.0.0"), 0o755)
		_ = os.WriteFile(e.p.target, []byte("v1.1.0"), 0o755)
		_ = os.MkdirAll(e.p.rootDir, 0o700)
		_ = e.p.save(&rootState{Schema: stateSchema, Trial: &rootTrial{Version: "v1.1.0", RolloutID: "r8"}})
		e.writeRequest(applyRequest{Schema: requestSchema, Kind: kindRollback, RolloutID: "r8", Version: "v1.1.0", Reason: "timeout"})
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "installed v1.0.0" {
			t.Fatal("not rolled back")
		}
		if r := e.result(); r.State != resRolledBack || r.RolloutID != "r8" {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("rollback request for a confirmed binary ignored", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.writeRequest(applyRequest{Schema: requestSchema, Kind: kindRollback, Version: "v1.0.0"})
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "installed v1.0.0" || e.restarts.Load() != 0 {
			t.Fatal("rolled back a binary that is not on probation")
		}
	})
	t.Run("no previous binary: rollback_failed", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.stage("v1.1.0", []byte("v1.1.0"), nil)
		e.onRestart = func(int32) { _ = os.Remove(e.p.target + ".prev") }
		if err := e.p.run(); err == nil {
			t.Fatal("impossible rollback reported success")
		}
		if r := e.result(); r.State != resRollbackFailed {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("nothing to do", func(t *testing.T) {
		e := newUpdaterEnv(t)
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		_ = os.RemoveAll(filepath.Dir(e.agentDir))
		if err := e.p.run(); err != nil {
			t.Fatal("missing agent state dir is not an error")
		}
	})
}
