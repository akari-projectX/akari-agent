//go:build linux

package main

// The privileged updater (M6, W18): `akari-agent -apply-update <agent state
// dir>`, run as root by akari-agent-update.service when the agent drops an
// apply request (akari-agent-update.path). It is always the INSTALLED,
// trusted binary (/usr/local/bin/akari-agent): nothing the agent downloaded
// is ever executed by anyone but systemd starting the freshly installed
// binary after this program verified it.
//
// Trust boundary: the agent's update directory is writable by the
// unprivileged agent, so everything in it is untrusted input:
//   - paths are opened component by component with O_NOFOLLOW (a symlink
//     planted by the agent fails the open), files must be regular, have one
//     link and belong to the agent (no hard link to a file of someone else);
//   - the request is verified from scratch: the Ed25519 signature under the
//     keys compiled into THIS binary, the manifest, platform, version policy
//     and this updater's own (root-only) record of rolled-back versions;
//   - TOCTOU: the staged bytes are first copied into a root-only file next
//     to the target, then that copy is verified (size + SHA-256 of what is
//     on disk), then it is renamed into place. The staged file is never
//     reopened after the check.
// Results go back as apply-result.json (created O_EXCL|O_NOFOLLOW under a
// temporary name, chowned to the agent, renamed into place).
//
// Units (W23): the systemd units of the NEW release are installed with its
// binary. They come only from the verified copy (`<copy> -print-units`,
// run before anything is replaced), never from the agent's directory, and
// only the known names (initSys.units) that already exist in the unit
// directory are replaced: written atomically (root, 0644), the previous
// ones kept in <updater state>/units.prev/ and put back on a rollback;
// `systemctl daemon-reload` before the restart. An updater unit from
// before W23 has the unit directory read-only (ProtectSystem=strict): the
// update then goes ahead without the units (EROFS, logged), and the agent
// reports the stale units ("stale-units") until the install command is run
// once.
//
// OpenRC (W32, -init openrc; Alpine): the same, with the init scripts
// (/etc/init.d/akari-agent and akari-agent-update, root 0755; OpenRC reads
// them at each start, nothing to reload), `rc-service akari-agent restart`,
// and supervise-daemon's state for the watch: its respawn counter
// (<RC_SVCDIR>/options/akari-agent/start_count) stands in for systemd's
// NRestarts, the service stopped and marked failed (respawn_max reached)
// or crashed (the supervisor gone) for systemd's start limit. The trigger
// is the akari-agent-update service's loop (openrc/akari-agent-update).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"akari/agent/release"
)

const (
	updaterStateFile = "updater.json"
	updaterLockFile  = "lock"
	// unitsPrevDir: the units replaced by the update on probation.
	unitsPrevDir = "units.prev"
	// printUnitsTimeout bounds `<new binary> -print-units`.
	printUnitsTimeout = 30 * time.Second
	// updaterGrace: the updater waits this much longer than the agent's
	// own self-check before it rolls back by itself.
	updaterGrace = time.Minute
)

// rootState is the updater's own record (root-only directory).
type rootState struct {
	Schema     int        `json:"schema"`
	RolledBack []string   `json:"rolled_back,omitempty"`
	Trial      *rootTrial `json:"trial,omitempty"`
}

type rootTrial struct {
	Version   string    `json:"version"`
	Previous  string    `json:"previous"`
	RolloutID string    `json:"rollout_id"`
	Started   time.Time `json:"started"`
	// Units: units.prev/ holds the units this update replaced (W23); a
	// rollback puts them back.
	Units bool `json:"units,omitempty"`
}

// applier is one run of the updater.
type applier struct {
	stateDir  string // the agent's state dir (contents untrusted)
	rootDir   string // the updater's own state (root-only)
	target    string // the installed binary
	version   string // this (installed) binary's version
	keys      []release.PublicKey
	goos      string
	goarch    string
	selfCheck time.Duration
	grace     time.Duration
	maxBoots  int
	poll      time.Duration
	// restart restarts the agent service (clearing a failed state first, so
	// a start limit the crash loop tripped cannot refuse it); unit reads
	// the service's state (systemd NRestarts, ActiveState, Result).
	restart func() error
	unit    func() (unitState, error)
	now     func() time.Time
	sleep   func(time.Duration)
	// W23: the init system (its unit names and modes), where the units
	// live, how a verified binary's units are read, and how the init
	// system is told about new unit files.
	init        *initSys
	unitDir     string
	unitsOf     func(binary string) (map[string][]byte, error)
	reloadUnits func() error
	// nft runs one nft transaction (R44 source filters; tests replace it).
	nft func(ctx context.Context, script string) error
}

func newApplier(stateDir, rootDir, target string, init *initSys, service string, keys []release.PublicKey) *applier {
	p := &applier{
		stateDir: stateDir, rootDir: rootDir, target: target, version: agentVersion, keys: keys,
		goos: runtime.GOOS, goarch: runtime.GOARCH,
		selfCheck: defaultSelfCheck, grace: updaterGrace, maxBoots: defaultMaxBoots, poll: time.Second,
		now:     time.Now,
		sleep:   time.Sleep,
		init:    init,
		unitDir: init.dir,
		unitsOf: func(binary string) (map[string][]byte, error) { return execPrintUnits(binary, init) },
		nft:     runNft,
	}
	if init == openrcInit {
		p.restart = func() error { return openrcRestart(service) }
		w := &openrcWatch{svcDir: openrcSvcDir, service: service, status: openrcStatus, alive: procAlive,
			now: func() time.Time { return p.now() }}
		p.unit = w.state
		// OpenRC reads the scripts at each start (and refreshes its
		// dependency cache when they are newer): nothing to reload.
		p.reloadUnits = func() error { return nil }
		return p
	}
	p.restart = func() error {
		// A unit that tripped its start limit (state failed) refuses
		// every start until reset: clear it before each restart.
		if out, err := exec.Command("systemctl", "reset-failed", service).CombinedOutput(); err != nil {
			slog.Warn("systemctl reset-failed", "error", err, "output", string(bytes.TrimSpace(out)))
		}
		out, err := exec.Command("systemctl", "restart", service).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart %s: %w: %s", service, err, bytes.TrimSpace(out))
		}
		return nil
	}
	p.unit = func() (unitState, error) {
		out, err := exec.Command("systemctl", "show", "-p", "ActiveState,SubState,Result,NRestarts", service).Output()
		if err != nil {
			return unitState{}, err
		}
		return parseUnitState(string(out))
	}
	p.reloadUnits = daemonReload
	return p
}

// unitState is what the updater reads of the agent service.
type unitState struct {
	Restarts int    // NRestarts: automatic restarts
	Active   string // ActiveState
	Sub      string // SubState
	Result   string // Result
}

// gaveUp reports systemd refusing further starts: the crash loop tripped
// StartLimitBurst, the unit is failed and NRestarts no longer grows.
func (u unitState) gaveUp() bool {
	return u.Active == "failed" || u.Result == "start-limit-hit"
}

// parseUnitState parses `systemctl show -p ...` output (Key=Value lines).
func parseUnitState(out string) (unitState, error) {
	var u unitState
	var err error
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "NRestarts":
			if u.Restarts, err = strconv.Atoi(v); err != nil {
				return u, err
			}
		case "ActiveState":
			u.Active = v
		case "SubState":
			u.Sub = v
		case "Result":
			u.Result = v
		}
	}
	return u, nil
}

// execPrintUnits runs a verified binary with -print-units (bounded time
// and output, empty environment) and parses what it prints (the files of
// init).
func execPrintUnits(binary string, init *initSys) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), printUnitsTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-print-units")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	var out limitedBuffer
	out.limit = 4 * maxUnitSize * len(allUnitNames())
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s -print-units: %w", filepath.Base(binary), err)
	}
	if out.over {
		return nil, errors.New("-print-units: output too large")
	}
	return init.parseUnits(out.Bytes())
}

// limitedBuffer keeps at most limit bytes (and notes when more came).
type limitedBuffer struct {
	bytes.Buffer
	limit int
	over  bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); len(p) > room {
		b.over = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func daemonReload() error {
	out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// runApplyUpdate is main's -apply-update mode.
func runApplyUpdate(stateDir, rootDir, target string, init *initSys, service, unitDir string, keys []release.PublicKey, selfCheck time.Duration, maxBoots int) error {
	if rootDir == "" {
		d := os.Getenv("STATE_DIRECTORY")
		if d == "" {
			return errors.New("-updater-state is required (or run under systemd with StateDirectory=)")
		}
		rootDir = strings.SplitN(d, ":", 2)[0]
	}
	if target == "" {
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("own executable: %w", err)
		}
		if p, err := filepath.EvalSymlinks(self); err == nil {
			self = p
		}
		target = self
	}
	p := newApplier(stateDir, rootDir, target, init, service, keys)
	if unitDir != "" {
		p.unitDir = unitDir
	}
	p.selfCheck = max(selfCheck, 10*time.Second)
	p.maxBoots = max(maxBoots, 1)
	return p.run()
}

func (p *applier) statePath() string { return filepath.Join(p.rootDir, updaterStateFile) }

func (p *applier) load() rootState {
	st := rootState{Schema: stateSchema}
	b, err := os.ReadFile(p.statePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("updater state unreadable; starting afresh", "error", err)
		}
		return st
	}
	if err := json.Unmarshal(b, &st); err != nil || st.Schema != stateSchema {
		slog.Error("updater state corrupt; starting afresh", "error", err)
		return rootState{Schema: stateSchema}
	}
	return st
}

func (p *applier) save(st *rootState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeSecret(p.statePath(), b)
}

func (p *applier) run() error {
	if err := os.MkdirAll(p.rootDir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(p.rootDir, updaterLockFile), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	st := p.load()
	if t := st.Trial; t != nil && t.Version != p.version {
		// The installed binary is not the one on probation (a reinstall,
		// or a rollback finished by an earlier run): nothing to watch.
		slog.Warn("dropping a stale probation record", "trial", t.Version, "installed", p.version)
		if t.Units && t.Previous == p.version {
			// Interrupted between the units and the binary: the previous
			// binary still runs, so do its units.
			p.restoreUnits(&st)
		}
		st.Trial = nil
		if err := p.save(&st); err != nil {
			return err
		}
	}
	d, err := openAgentDir(p.stateDir)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.close()
	// R44: the source allowlists first (seconds matter there; an update
	// may keep this run busy for minutes).
	p.applySourceFilters(d)
	if t := st.Trial; t != nil && d.confirmed(t.Version) {
		// Passed while no updater watched (e.g. across a reboot).
		slog.Info("agent update passed its self-check", "version", t.Version)
		st.Trial = nil
		if err := p.save(&st); err != nil {
			return err
		}
		_ = d.remove(confirmedName)
		_ = d.writeResult(applyResult{State: resConfirmed, Version: t.Version, RolloutID: t.RolloutID})
	}
	req, err := d.takeRequest()
	if err != nil {
		return fmt.Errorf("apply request: %w", err)
	}
	if req == nil {
		return nil
	}
	switch req.Kind {
	case kindApply:
		return p.apply(d, &st, req)
	case kindRollback:
		t := st.Trial
		if t == nil || t.Version != req.Version || d.confirmed(t.Version) {
			slog.Info("rollback request for a binary that is not on probation; ignored", "version", req.Version)
			return nil
		}
		return p.rollback(d, &st, t.Version, t.RolloutID, "self-check failed: "+req.Reason)
	}
	return d.writeResult(applyResult{State: resRejected, Version: req.Version, RolloutID: req.RolloutID,
		Error: fmt.Sprintf("unknown request kind %q", req.Kind)})
}

// apply verifies, installs and watches one update.
func (p *applier) apply(d *agentDir, st *rootState, req *applyRequest) error {
	reject := func(err error) error {
		slog.Error("agent update refused", "version", req.Version, "error", err)
		return d.writeResult(applyResult{State: resRejected, Version: req.Version, RolloutID: req.RolloutID,
			Error: truncate(err.Error(), 512)})
	}
	if t := st.Trial; t != nil {
		return reject(fmt.Errorf("the update to %s is still on probation", t.Version))
	}
	m, keyID, err := p.verify(st, req)
	if err != nil {
		return reject(err)
	}
	tmp, err := p.copyStaged(d, m)
	if err != nil {
		return reject(err)
	}
	// W23: the units the new release carries, from the verified copy.
	units, err := p.unitsOf(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return reject(fmt.Errorf("the release's %s units: %w", p.init.name, err))
	}
	st.Trial = &rootTrial{Version: m.Version, Previous: p.version, RolloutID: req.RolloutID, Started: p.now().UTC()}
	if err := p.save(st); err != nil {
		_ = os.Remove(tmp)
		return reject(fmt.Errorf("record the probation: %w", err))
	}
	if err := p.installUnits(st, units); err != nil {
		_ = os.Remove(tmp)
		p.restoreUnits(st)
		st.Trial = nil
		_ = p.save(st)
		return reject(fmt.Errorf("install the units: %w", err))
	}
	if err := p.install(tmp); err != nil {
		_ = os.Remove(tmp)
		p.restoreUnits(st)
		st.Trial = nil
		_ = p.save(st)
		return reject(fmt.Errorf("install: %w", err))
	}
	_ = d.remove(stagedName)
	slog.Info("agent update installed; restarting the agent", "version", m.Version, "key", keyID,
		"previous", p.version, "target", p.target)
	if err := d.writeResult(applyResult{State: resInstalled, Version: m.Version, RolloutID: req.RolloutID}); err != nil {
		return p.rollback(d, st, m.Version, req.RolloutID, "cannot tell the agent: "+err.Error())
	}
	if err := p.restart(); err != nil {
		return p.rollback(d, st, m.Version, req.RolloutID, err.Error())
	}
	base := -1
	st0, err := p.unit()
	if err == nil && st0.Restarts >= 0 {
		base = st0.Restarts
	} else {
		slog.Warn("cannot read the agent's restart counter; relying on the self-check timeout", "error", err)
	}
	if why := p.watch(d, m.Version, base); why != "" {
		return p.rollback(d, st, m.Version, req.RolloutID, why)
	}
	st.Trial = nil
	if err := p.save(st); err != nil {
		return err
	}
	_ = d.remove(confirmedName)
	err = d.writeResult(applyResult{State: resConfirmed, Version: m.Version, RolloutID: req.RolloutID})
	slog.Info("agent update passed its self-check", "version", m.Version)
	return err
}

// verify judges the request with this binary's own keys and policy. The
// agent's verdict counts for nothing.
func (p *applier) verify(st *rootState, req *applyRequest) (*release.Manifest, string, error) {
	keyID, err := release.Verify(req.Manifest, req.Signatures, p.keys)
	if err != nil {
		return nil, "", err
	}
	m, err := release.ParseManifest(req.Manifest)
	if err != nil {
		return nil, "", err
	}
	if m.Version != req.Version {
		return nil, "", fmt.Errorf("request names %q, the signed manifest %s", req.Version, m.Version)
	}
	policy := release.Policy{Running: p.version, OS: p.goos, Arch: p.goarch, PanelProtocol: req.PanelProtocol,
		RolledBack: func(v string) bool { return slices.Contains(st.RolledBack, v) }}
	if err := policy.Check(m); err != nil {
		return nil, "", err
	}
	return m, keyID, nil
}

// copyStaged copies the agent's staged file into a root-only file next to
// the target and verifies THAT copy. Returns its path.
func (p *applier) copyStaged(d *agentDir, m *release.Manifest) (string, error) {
	src, size, err := d.open(stagedName, release.MaxArtifactSize)
	if err != nil {
		return "", fmt.Errorf("staged binary: %w", err)
	}
	defer src.Close()
	if size != m.Size {
		return "", fmt.Errorf("staged binary is %d bytes, the signed manifest says %d", size, m.Size)
	}
	tmp := filepath.Join(filepath.Dir(p.target), "."+filepath.Base(p.target)+".new")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o700)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	_, err = io.Copy(f, io.LimitReader(src, m.Size+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("copy: %w", err)
	}
	// The copy is root-only from here on: verify exactly what will run.
	sum, n, err := fileDigest(tmp, m.Size)
	if err != nil {
		return "", err
	}
	if n != m.Size || sum != m.SHA256 {
		return "", fmt.Errorf("staged binary does not match the signed manifest (%d bytes, sha256 %s)", n, sum)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	ok = true
	return tmp, nil
}

// install keeps the running binary as <target>.prev and renames the
// verified copy into place (atomic for anyone starting the target).
func (p *applier) install(tmp string) error {
	prev := p.target + ".prev"
	ptmp := prev + ".tmp"
	_ = os.Remove(ptmp)
	if err := os.Link(p.target, ptmp); err != nil {
		return fmt.Errorf("keep the previous binary: %w", err)
	}
	if err := os.Rename(ptmp, prev); err != nil {
		_ = os.Remove(ptmp)
		return fmt.Errorf("keep the previous binary: %w", err)
	}
	if err := os.Rename(tmp, p.target); err != nil {
		return err
	}
	syncDir(filepath.Dir(p.target))
	return nil
}

// watch waits for the new binary's self-check. Returns "" when it passed,
// else why it failed.
func (p *applier) watch(d *agentDir, version string, base int) string {
	deadline := p.now().Add(p.selfCheck + p.grace)
	for {
		if d.confirmed(version) {
			return ""
		}
		if r := d.takeRollback(version); r != nil {
			return "self-check failed: " + r.Reason
		}
		if u, err := p.unit(); err == nil {
			if u.gaveUp() {
				return fmt.Sprintf("the new agent crash-looped into %s's start limit (state %s/%s, result %s) without passing its self-check", p.init.name, u.Active, u.Sub, u.Result)
			}
			if base >= 0 && u.Restarts-base >= p.maxBoots {
				return fmt.Sprintf("the new agent stopped %d times without passing its self-check", u.Restarts-base)
			}
		}
		if p.now().After(deadline) {
			return fmt.Sprintf("no connected, acknowledged apply within %s of the restart", p.selfCheck+p.grace)
		}
		// The agent on probation may ask for its source filters meanwhile.
		p.applySourceFilters(d)
		p.sleep(p.poll)
	}
}

// rollback puts <target>.prev back, records the failed version (never
// accepted again) and restarts the agent, which reports ROLLED_BACK.
func (p *applier) rollback(d *agentDir, st *rootState, version, rollout, why string) error {
	slog.Error("rolling back agent update", "version", version, "reason", why)
	p.restoreUnits(st)
	st.Trial = nil
	if err := os.Rename(p.target+".prev", p.target); err != nil {
		_ = p.save(st)
		_ = d.writeResult(applyResult{State: resRollbackFailed, Version: version, RolloutID: rollout,
			Error: truncate(why+"; rollback impossible: "+err.Error(), 512)})
		return fmt.Errorf("rollback: %w", err)
	}
	syncDir(filepath.Dir(p.target))
	if !slices.Contains(st.RolledBack, version) {
		st.RolledBack = append(st.RolledBack, version)
		if len(st.RolledBack) > maxRolledBack {
			st.RolledBack = st.RolledBack[len(st.RolledBack)-maxRolledBack:]
		}
	}
	serr := p.save(st)
	_ = d.remove(confirmedName)
	werr := d.writeResult(applyResult{State: resRolledBack, Version: version, RolloutID: rollout,
		Error: truncate(why, 512)})
	if err := p.restart(); err != nil {
		return err
	}
	return errors.Join(serr, werr)
}

// installUnits replaces the known units that exist in the unit directory
// with the new release's (identical ones are left alone), keeping the
// replaced ones in units.prev/ (recorded in the trial before anything is
// written), then reloads systemd. A read-only unit directory (an updater
// unit from before W23) is not an error: the update goes ahead without the
// units.
func (p *applier) installUnits(st *rootState, units map[string][]byte) error {
	prevDir := filepath.Join(p.rootDir, unitsPrevDir)
	if err := os.RemoveAll(prevDir); err != nil {
		return err
	}
	if err := os.Mkdir(prevDir, 0o700); err != nil {
		return err
	}
	var change []string
	for _, n := range p.init.units {
		cur, err := readUnit(filepath.Join(p.unitDir, n))
		if errors.Is(err, os.ErrNotExist) {
			continue // never create a unit the node does not have
		}
		if err != nil {
			return err
		}
		if bytes.Equal(cur, units[n]) {
			continue
		}
		if err := writeSecret(filepath.Join(prevDir, n), cur); err != nil {
			return err
		}
		change = append(change, n)
	}
	if len(change) == 0 {
		return nil
	}
	st.Trial.Units = true
	if err := p.save(st); err != nil {
		return err
	}
	for i, n := range change {
		err := writeUnitFile(p.unitDir, n, units[n], p.init.mode)
		if i == 0 && errors.Is(err, unix.EROFS) {
			slog.Warn(p.init.name+" units NOT refreshed: this node's updater unit predates unit refresh "+
				"(its unit directory is read-only); run the panel's install command (重装命令) once",
				"dir", p.unitDir)
			st.Trial.Units = false
			return p.save(st)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
	}
	syncDir(p.unitDir)
	if err := p.reloadUnits(); err != nil {
		return err
	}
	slog.Info("installed the new release's "+p.init.name+" units", "units", change)
	return nil
}

// restoreUnits puts back the units the update on probation replaced (best
// effort: a failure is logged, the binary rollback goes on).
func (p *applier) restoreUnits(st *rootState) {
	if st.Trial == nil || !st.Trial.Units {
		return
	}
	prevDir := filepath.Join(p.rootDir, unitsPrevDir)
	var restored []string
	for _, n := range p.init.units {
		b, err := readUnit(filepath.Join(prevDir, n))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			err = writeUnitFile(p.unitDir, n, b, p.init.mode)
		}
		if err != nil {
			slog.Error("cannot restore the previous "+p.init.name+" unit", "unit", n, "error", err)
			continue
		}
		restored = append(restored, n)
	}
	st.Trial.Units = false
	if len(restored) == 0 {
		return
	}
	syncDir(p.unitDir)
	if err := p.reloadUnits(); err != nil {
		slog.Error(p.init.name+" reload after restoring the units", "error", err)
	}
	slog.Info("restored the previous "+p.init.name+" units", "units", restored)
}

// readUnit reads a unit file (no symlink followed, regular, bounded).
func readUnit(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxUnitSize {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, maxUnitSize)
	}
	return io.ReadAll(io.LimitReader(f, maxUnitSize))
}

// writeUnitFile is writeUnit (tests simulate a read-only unit directory).
var writeUnitFile = writeUnit

// writeUnit atomically replaces dir/name: a new root-owned file of mode
// (O_EXCL, no symlink followed), synced, renamed over the old one.
func writeUnit(dir, name string, b []byte, mode os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".akari-new")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode) // explicit: the unit's UMask=0077 would make it 0600
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func fileDigest(path string, limit int64) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return digest(f, limit)
}

// --- the agent's directory, opened without following anything ---------------

type agentDir struct {
	fd       int
	uid, gid uint32
}

// openAgentDir opens <state>/update: the state dir itself sits in a
// root-owned parent (/var/lib/private); neither it nor update/ may be a
// symlink, and update/ must belong to the state dir's owner.
func openAgentDir(stateDir string) (*agentDir, error) {
	sfd, err := unix.Open(stateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(sfd)
	var sst unix.Stat_t
	if err := unix.Fstat(sfd, &sst); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(sfd, updateDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Uid != sst.Uid {
		unix.Close(fd)
		return nil, fmt.Errorf("%s/%s belongs to uid %d, the state dir to %d", stateDir, updateDirName, st.Uid, sst.Uid)
	}
	return &agentDir{fd: fd, uid: st.Uid, gid: st.Gid}, nil
}

func (d *agentDir) close() { unix.Close(d.fd) }

// open opens an agent file for reading: no symlink, regular, one link,
// owned by the agent, at most limit bytes.
func (d *agentDir) open(name string, limit int64) (*os.File, int64, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, 0, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		err = fmt.Errorf("%s is not a regular file", name)
	case st.Nlink != 1:
		err = fmt.Errorf("%s has %d links", name, st.Nlink)
	case st.Uid != d.uid:
		err = fmt.Errorf("%s belongs to uid %d, not the agent (%d)", name, st.Uid, d.uid)
	case st.Size > limit:
		err = fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	if err != nil {
		unix.Close(fd)
		return nil, 0, err
	}
	return os.NewFile(uintptr(fd), name), st.Size, nil
}

func (d *agentDir) read(name string, limit int64) ([]byte, error) {
	f, _, err := d.open(name, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

func (d *agentDir) remove(name string) error {
	err := unix.Unlinkat(d.fd, name, 0)
	if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EPERM) {
		err = unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR)
	}
	return err
}

// confirmed: the agent recorded that version passed its self-check.
func (d *agentDir) confirmed(version string) bool {
	b, err := d.read(confirmedName, 256)
	return err == nil && string(b) == version
}

// takeRequest consumes the apply request (removed first, so the path unit
// cannot loop on it whatever it contains). nil when there is none.
func (d *agentDir) takeRequest() (*applyRequest, error) {
	f, _, err := d.open(requestName, maxRequestSize)
	_ = d.remove(requestName)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRequestSize))
	if err != nil {
		return nil, err
	}
	return parseApplyRequest(b)
}

// takeRollback consumes a rollback request for version (anything else in
// the request file is left for the next run).
func (d *agentDir) takeRollback(version string) *applyRequest {
	b, err := d.read(requestName, maxRequestSize)
	if err != nil {
		return nil
	}
	r, err := parseApplyRequest(b)
	if err != nil || r.Kind != kindRollback || r.Version != version {
		return nil
	}
	_ = d.remove(requestName)
	return r
}

// writeResult hands a verdict to the agent: a new file (O_EXCL, no
// symlink followed) chowned to the agent, renamed over the old one.
func (d *agentDir) writeResult(r applyResult) error {
	r.Schema = requestSchema
	b, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	return d.writeFile(resultName, b)
}

// writeFile creates name in the agent's directory with b: a new file
// (O_EXCL, no symlink followed) chowned to the agent, renamed over the old
// one.
func (d *agentDir) writeFile(name string, b []byte) error {
	tmp := fmt.Sprintf(".%s.%d.tmp", name, os.Getpid())
	_ = unix.Unlinkat(d.fd, tmp, 0)
	fd, err := unix.Openat(d.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(b)
	if err == nil {
		err = unix.Fchown(fd, int(d.uid), int(d.gid))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(d.fd, tmp, d.fd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(d.fd, tmp, 0)
		return err
	}
	return unix.Fsync(d.fd)
}
