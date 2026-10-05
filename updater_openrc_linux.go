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
// reached) or is gone (crashed, unsupervised).
func openrcUnitState(svcDir, service string, status func(string) (int, error)) (unitState, error) {
	code, err := status(service)
	if err != nil {
		return unitState{}, fmt.Errorf("rc-service %s status: %w", service, err)
	}
	u := unitState{Restarts: -1}
	switch code {
	case rcStarted:
		u.Active, u.Sub = "active", "started"
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
