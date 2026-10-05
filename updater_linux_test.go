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
	// W23: the node's unit directory, the units the staged release
	// carries, and systemd reloads.
	unitDir  string
	newUnits map[string][]byte
	unitsErr error
	reloads  atomic.Int32
}

// oldUnits: what the node runs before the update (W23).
func oldUnits() map[string][]byte { return oldUnitsOf(systemdInit) }

func oldUnitsOf(s *initSys) map[string][]byte {
	out := map[string][]byte{}
	for _, n := range s.units {
		out[n] = []byte("# old " + n + "\n[Unit]\n")
	}
	return out
}

func (e *updaterEnv) unit(name string) string {
	b, err := os.ReadFile(filepath.Join(e.unitDir, name))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func newUpdaterEnv(t *testing.T) *updaterEnv { t.Helper(); return newUpdaterEnvFor(t, systemdInit) }

func newUpdaterEnvFor(t *testing.T, init *initSys) *updaterEnv {
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
	p := newApplier(state, filepath.Join(root, "var/lib/akari-agent-update"), target, init, init.service,
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
	p.unit = func() (unitState, error) { return unitState{Restarts: int(e.nRestart.Load()), Active: "active"}, nil }
	e.unitDir = filepath.Join(root, strings.TrimPrefix(init.dir, "/"))
	if err := os.MkdirAll(e.unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range oldUnitsOf(init) {
		if err := os.WriteFile(filepath.Join(e.unitDir, n), b, init.mode); err != nil {
			t.Fatal(err)
		}
	}
	e.newUnits = init.embeddedUnits()
	p.unitDir = e.unitDir
	p.unitsOf = func(bin string) (map[string][]byte, error) {
		// Read from the verified root-only copy, never the staged file.
		if filepath.Dir(bin) != filepath.Dir(p.target) {
			t.Errorf("units read from %s", bin)
		}
		return e.newUnits, e.unitsErr
	}
	p.reloadUnits = func() error { e.reloads.Add(1); return nil }
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
	// W23: the new release's units are installed (root 0644), systemd
	// reloaded once; the replaced ones are kept.
	for _, n := range systemdInit.units {
		if e.unit(n) != string(e.newUnits[n]) {
			t.Fatalf("%s not refreshed: %q", n, e.unit(n))
		}
		if fi, _ := os.Stat(filepath.Join(e.unitDir, n)); fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode %v", n, fi.Mode().Perm())
		}
		if prev, _ := os.ReadFile(filepath.Join(e.p.rootDir, unitsPrevDir, n)); string(prev) != string(oldUnits()[n]) {
			t.Fatalf("%s: previous unit not kept: %q", n, prev)
		}
	}
	if e.reloads.Load() != 1 {
		t.Fatalf("reloads %d", e.reloads.Load())
	}
	if left, _ := filepath.Glob(filepath.Join(e.unitDir, ".*")); len(left) != 0 {
		t.Fatalf("temp files in the unit dir: %v", left)
	}
}

// W23: what the updater does with the units of the release it installs.
func TestApplyUnits(t *testing.T) {
	t.Run("identical units: nothing written, no reload", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.newUnits = oldUnits()
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		e.onRestart = func(int32) { e.confirm("v1.1.0") }
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.reloads.Load() != 0 || e.result().State != resConfirmed {
			t.Fatalf("reloads %d result %+v", e.reloads.Load(), e.result())
		}
	})
	t.Run("only units the node has are replaced", func(t *testing.T) {
		e := newUpdaterEnv(t)
		if err := os.Remove(filepath.Join(e.unitDir, "akari-agent-update.path")); err != nil {
			t.Fatal(err)
		}
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		e.onRestart = func(int32) { e.confirm("v1.1.0") }
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(e.unitDir, "akari-agent-update.path")); !os.IsNotExist(err) {
			t.Fatal("a unit the node did not have was created")
		}
		if e.unit("akari-agent.service") != string(e.newUnits["akari-agent.service"]) {
			t.Fatal("agent unit not refreshed")
		}
	})
	t.Run("a release without readable units is refused", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.unitsErr = errors.New("units: akari-agent.service missing")
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if r := e.result(); r.State != resRejected || !strings.Contains(r.Error, "systemd units") {
			t.Fatalf("result %+v", r)
		}
		if e.installed() != "installed v1.0.0" || e.unit("akari-agent.service") != string(oldUnits()["akari-agent.service"]) {
			t.Fatal("node changed")
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.p.target), ".*")); len(left) != 0 {
			t.Fatalf("temp files next to the target: %v", left)
		}
	})
	t.Run("pre-W23 updater unit (read-only unit dir): update without the units", func(t *testing.T) {
		e := newUpdaterEnv(t)
		writeUnitFile = func(string, string, []byte, os.FileMode) error { return &os.PathError{Op: "open", Err: syscall.EROFS} }
		t.Cleanup(func() { writeUnitFile = writeUnit })
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		e.onRestart = func(int32) { e.confirm("v1.1.0") }
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "new agent v1.1.0" || e.result().State != resConfirmed {
			t.Fatalf("installed %q result %+v", e.installed(), e.result())
		}
		if e.unit("akari-agent.service") != string(oldUnits()["akari-agent.service"]) || e.reloads.Load() != 0 {
			t.Fatal("units touched")
		}
	})
	t.Run("a unit write failure refuses the update and restores", func(t *testing.T) {
		e := newUpdaterEnv(t)
		n := 0
		writeUnitFile = func(dir, name string, b []byte, mode os.FileMode) error {
			if n++; n == 2 {
				return errors.New("disk full")
			}
			return writeUnit(dir, name, b, mode)
		}
		t.Cleanup(func() { writeUnitFile = writeUnit })
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if r := e.result(); r.State != resRejected || !strings.Contains(r.Error, "disk full") {
			t.Fatalf("result %+v", r)
		}
		for _, u := range systemdInit.units {
			if e.unit(u) != string(oldUnits()[u]) {
				t.Fatalf("%s not restored: %q", u, e.unit(u))
			}
		}
		if e.installed() != "installed v1.0.0" || e.rootState().Trial != nil {
			t.Fatalf("installed %q trial %+v", e.installed(), e.rootState().Trial)
		}
	})
	t.Run("rollback in a later run (agent request) restores the units", func(t *testing.T) {
		e := newUpdaterEnv(t)
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		e.p.selfCheck, e.p.grace = 0, 0 // this run gives up at once ...
		e.onRestart = func(n int32) {
			if n == 1 {
				// ... no: simulate the updater dying after the restart.
				panic(errStop)
			}
		}
		func() {
			defer func() {
				if r := recover(); r != errStop {
					panic(r)
				}
			}()
			_ = e.p.run()
		}()
		if e.unit("akari-agent.service") != string(e.newUnits["akari-agent.service"]) || !e.rootState().Trial.Units {
			t.Fatalf("units not installed / not recorded: %+v", e.rootState().Trial)
		}
		// The next run is a fresh process of the NEW binary.
		e.onRestart = nil
		e.p.version = "v1.1.0"
		e.writeRequest(applyRequest{Schema: requestSchema, Kind: kindRollback, RolloutID: "r1", Version: "v1.1.0", Reason: "no ack"})
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "installed v1.0.0" || e.result().State != resRolledBack {
			t.Fatalf("installed %q result %+v", e.installed(), e.result())
		}
		for _, u := range systemdInit.units {
			if e.unit(u) != string(oldUnits()[u]) {
				t.Fatalf("%s not restored: %q", u, e.unit(u))
			}
		}
		if e.reloads.Load() != 2 {
			t.Fatalf("reloads %d (install + restore)", e.reloads.Load())
		}
	})
}

var errStop = errors.New("stop")

// W23: an updater that died after installing the units but before the
// binary leaves the previous binary with the new units: the next run puts
// the previous units back.
func TestApplyInterruptedBeforeTheBinary(t *testing.T) {
	e := newUpdaterEnv(t)
	e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
	n := 0
	writeUnitFile = func(dir, name string, b []byte, mode os.FileMode) error {
		err := writeUnit(dir, name, b, mode)
		if n++; n == len(systemdInit.units) {
			panic(errStop) // the last unit written, then the process dies
		}
		return err
	}
	t.Cleanup(func() { writeUnitFile = writeUnit })
	func() {
		defer func() {
			if r := recover(); r != errStop {
				panic(r)
			}
		}()
		_ = e.p.run()
	}()
	writeUnitFile = writeUnit
	if e.installed() != "installed v1.0.0" || e.unit("akari-agent.service") != string(e.newUnits["akari-agent.service"]) {
		t.Fatalf("setup: installed %q", e.installed())
	}
	if err := e.p.run(); err != nil { // the next trigger (still the old binary)
		t.Fatal(err)
	}
	for _, u := range systemdInit.units {
		if e.unit(u) != string(oldUnits()[u]) {
			t.Fatalf("%s not restored: %q", u, e.unit(u))
		}
	}
	if e.rootState().Trial != nil {
		t.Fatal("probation kept")
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
					e.p.unit = func() (unitState, error) {
						return unitState{Restarts: int(e.nRestart.Add(1)), Active: "activating", Sub: "auto-restart"}, nil
					}
				}
			}
		}},
		// StartLimitBurst tripped: the unit is failed, NRestarts frozen.
		{"start limit", "start limit", func(e *updaterEnv) func(int32) {
			return func(n int32) {
				if n == 1 {
					e.p.unit = func() (unitState, error) {
						return unitState{Restarts: 4, Active: "failed", Sub: "failed", Result: "start-limit-hit"}, nil
					}
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
			// W23: the previous units are back, systemd reloaded twice.
			for _, u := range systemdInit.units {
				if e.unit(u) != string(oldUnits()[u]) {
					t.Fatalf("%s not restored: %q", u, e.unit(u))
				}
			}
			if e.reloads.Load() != 2 {
				t.Fatalf("reloads %d", e.reloads.Load())
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

func TestParseUnitState(t *testing.T) {
	u, err := parseUnitState("Result=start-limit-hit\nNRestarts=4\nActiveState=failed\nSubState=failed\n")
	if err != nil || u != (unitState{Restarts: 4, Active: "failed", Sub: "failed", Result: "start-limit-hit"}) || !u.gaveUp() {
		t.Fatalf("%+v %v", u, err)
	}
	u, _ = parseUnitState("Result=success\nNRestarts=2\nActiveState=activating\nSubState=auto-restart\n")
	if u.gaveUp() {
		t.Fatalf("a restarting unit is not given up: %+v", u)
	}
}

// W32: under OpenRC the updater installs the release's init scripts
// (executable) and puts them back on a rollback, as it does the systemd
// units.
func TestApplyOpenRC(t *testing.T) {
	t.Run("installed with the binary and confirmed", func(t *testing.T) {
		e := newUpdaterEnvFor(t, openrcInit)
		e.stage("v1.1.0", []byte("new agent v1.1.0"), nil)
		e.onRestart = func(int32) { e.confirm("v1.1.0") }
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "new agent v1.1.0" || e.result().State != resConfirmed {
			t.Fatalf("installed %q result %+v", e.installed(), e.result())
		}
		for _, n := range openrcInit.units {
			if e.unit(n) != string(e.newUnits[n]) {
				t.Fatalf("%s not refreshed: %q", n, e.unit(n))
			}
			if fi, _ := os.Stat(filepath.Join(e.unitDir, n)); fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s mode %v", n, fi.Mode().Perm())
			}
		}
		for _, n := range systemdInit.units {
			if _, err := os.Stat(filepath.Join(e.unitDir, n)); !os.IsNotExist(err) {
				t.Fatalf("systemd unit %s written on an OpenRC node", n)
			}
		}
	})
	t.Run("respawn loop: binary and scripts rolled back", func(t *testing.T) {
		e := newUpdaterEnvFor(t, openrcInit)
		e.stage("v1.1.0", []byte("broken v1.1.0"), nil)
		e.onRestart = func(n int32) {
			if n == 1 {
				e.p.unit = func() (unitState, error) {
					return unitState{Restarts: int(e.nRestart.Add(1)), Active: "active", Sub: "started"}, nil
				}
			}
		}
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if e.installed() != "installed v1.0.0" || e.result().State != resRolledBack {
			t.Fatalf("installed %q result %+v", e.installed(), e.result())
		}
		for _, n := range openrcInit.units {
			if e.unit(n) != string(oldUnitsOf(openrcInit)[n]) {
				t.Fatalf("%s not restored: %q", n, e.unit(n))
			}
			if fi, _ := os.Stat(filepath.Join(e.unitDir, n)); fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s mode %v after the restore", n, fi.Mode().Perm())
			}
		}
	})
	t.Run("supervise-daemon gave up: fast rollback", func(t *testing.T) {
		e := newUpdaterEnvFor(t, openrcInit)
		e.stage("v1.1.0", []byte("broken v1.1.0"), nil)
		e.onRestart = func(n int32) {
			if n == 1 {
				e.p.unit = func() (unitState, error) {
					return unitState{Restarts: 1, Active: "failed", Sub: "stopped", Result: "respawn-limit"}, nil
				}
			}
		}
		if err := e.p.run(); err != nil {
			t.Fatal(err)
		}
		if r := e.result(); r.State != resRolledBack || !strings.Contains(r.Error, "openrc's start limit") {
			t.Fatalf("result %+v", r)
		}
	})
}

func TestOpenRCUnitState(t *testing.T) {
	dir := t.TempDir()
	opts := filepath.Join(dir, "options", "akari-agent")
	if err := os.MkdirAll(opts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "failed"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := func(code int, err error) func(string) (int, error) {
		return func(svc string) (int, error) {
			if svc != "akari-agent" {
				t.Errorf("service %q", svc)
			}
			return code, err
		}
	}
	u, err := openrcUnitState(dir, "akari-agent", st(rcStarted, nil))
	if err != nil || u.Restarts != -1 || u.gaveUp() {
		t.Fatalf("no counter: %+v %v", u, err)
	}
	if err := os.WriteFile(filepath.Join(opts, "start_count"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if u, err = openrcUnitState(dir, "akari-agent", st(rcStarted, nil)); err != nil || u.Restarts != 2 || u.gaveUp() {
		t.Fatalf("started: %+v %v", u, err)
	}
	// Stopped by hand: not a give-up.
	if u, err = openrcUnitState(dir, "akari-agent", st(rcStopped, nil)); err != nil || u.gaveUp() {
		t.Fatalf("stopped: %+v %v", u, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "failed", "akari-agent"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if u, err = openrcUnitState(dir, "akari-agent", st(rcStopped, nil)); err != nil || !u.gaveUp() {
		t.Fatalf("respawn_max reached: %+v %v", u, err)
	}
	for _, c := range []int{rcCrashed, rcUnsupervised} {
		if u, err = openrcUnitState(dir, "akari-agent", st(c, nil)); err != nil || !u.gaveUp() {
			t.Fatalf("status %d: %+v %v", c, u, err)
		}
	}
	if _, err = openrcUnitState(dir, "akari-agent", st(0, errors.New("no rc-service"))); err == nil {
		t.Fatal("status error swallowed")
	}
	if err := os.WriteFile(filepath.Join(opts, "start_count"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = openrcUnitState(dir, "akari-agent", st(rcStarted, nil)); err == nil {
		t.Fatal("garbage counter accepted")
	}
}
