//go:build linux

package main

// OpenRC (W32, Alpine): how the privileged updater restarts the agent and
// reads its state under supervise-daemon (the systemd equivalents are in
// newApplier). openrc/akari-agent-update runs the updater.

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	rcService = "/sbin/rc-service"
	// openrcSvcDir: OpenRC's state directory (RC_SVCDIR).
	openrcSvcDir = "/run/openrc"
)

// `rc-service NAME status` exit codes (OpenRC's service states).
const (
	rcStarted      = 0
	rcStopped      = 3
	rcCrashed      = 32 // the supervisor is gone, the service still marked started
	rcUnsupervised = 64 // supervise-daemon no longer answers
)

// openrcStuckAfter: how long the service may stay "started" while the
// child supervise-daemon recorded is gone before the updater calls it a
// failed boot. supervise-daemon respawns after respawn_delay (3 s), but a
// child that dies at once can be missed by it (seen on loaded CI hosts:
// the service stays "started", nothing is respawned): without this the
// updater would only notice at the self-check timeout.
const openrcStuckAfter = 15 * time.Second

// openrcWatch reads the agent service's state for the watch, turning a
// child that stays gone into a give-up.
type openrcWatch struct {
	svcDir, service string
	status          func(string) (int, error)
	alive           func(pid int) bool
	now             func() time.Time
	goneSince       time.Time
}

func (w *openrcWatch) state() (unitState, error) {
	u, err := openrcUnitState(w.svcDir, w.service, w.status, w.alive)
	if err != nil || u.Sub != "child-gone" {
		w.goneSince = time.Time{}
		return u, err
	}
	if w.goneSince.IsZero() {
		w.goneSince = w.now()
	} else if w.now().Sub(w.goneSince) >= openrcStuckAfter {
		u.Active, u.Result = "failed", "child-gone"
	}
	return u, nil
}

// procAlive: pid exists and is not a zombie.
func procAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// pid (comm) STATE ...: comm may hold spaces and parentheses.
	i := bytes.LastIndexByte(b, ')')
	return i < 0 || i+2 >= len(b) || b[i+2] != 'Z'
}

// openrcRestart restarts the agent service. A service whose supervisor is
// gone refuses an orderly restart: it is reset to stopped (zap) and
// started. A service that gave up after respawn_max is plainly stopped and
// restarts like any other.
func openrcRestart(service string) error {
	out, err := exec.Command(rcService, service, "restart").CombinedOutput()
	if err == nil {
		return nil
	}
	slog.Warn("rc-service restart failed; resetting the service and starting it", "service", service,
		"error", err, "output", string(bytes.TrimSpace(out)))
	if out, err := exec.Command(rcService, service, "zap").CombinedOutput(); err != nil {
		slog.Warn("rc-service zap", "error", err, "output", string(bytes.TrimSpace(out)))
	}
	out, err = exec.Command(rcService, service, "start").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rc-service %s start: %w: %s", service, err, bytes.TrimSpace(out))
	}
	return nil
}

// openrcStatus is the exit code of `rc-service NAME status`.
func openrcStatus(service string) (int, error) {
	err := exec.Command(rcService, service, "status").Run()
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

// openrcUnitState maps the service's OpenRC state onto unitState:
// Restarts = supervise-daemon's respawn counter (start_count, reset by
// every start; -1 when this OpenRC does not keep one), Active "failed"
// when supervise-daemon gave up (stopped and marked failed: respawn_max
// reached) or is gone (crashed, unsupervised); Sub "child-gone" when the
// service is started but the child supervise-daemon recorded (child_pid)
// is not alive (openrcWatch decides when that is a failure).
func openrcUnitState(svcDir, service string, status func(string) (int, error), alive func(int) bool) (unitState, error) {
	code, err := status(service)
	if err != nil {
		return unitState{}, fmt.Errorf("rc-service %s status: %w", service, err)
	}
	u := unitState{Restarts: -1}
	switch code {
	case rcStarted:
		u.Active, u.Sub = "active", "started"
		if b, err := os.ReadFile(filepath.Join(svcDir, "options", service, "child_pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 && !alive(pid) {
				u.Sub = "child-gone"
			}
		}
	case rcStopped:
		u.Active, u.Sub = "inactive", "stopped"
		if _, err := os.Stat(filepath.Join(svcDir, "failed", service)); err == nil {
			u.Active, u.Result = "failed", "respawn-limit"
		}
	case rcCrashed:
		u.Active, u.Sub, u.Result = "failed", "crashed", "supervisor-gone"
	case rcUnsupervised:
		u.Active, u.Sub, u.Result = "failed", "unsupervised", "supervisor-gone"
	default:
		u.Active, u.Sub = "other", strconv.Itoa(code)
	}
	b, err := os.ReadFile(filepath.Join(svcDir, "options", service, "start_count"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return u, err
	default:
		if u.Restarts, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil || u.Restarts < 0 {
			return u, fmt.Errorf("start_count %q: not a count", bytes.TrimSpace(b))
		}
	}
	return u, nil
}
