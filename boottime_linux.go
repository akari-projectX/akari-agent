//go:build linux

package main

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootClock returns time since boot on CLOCK_BOOTTIME, which (unlike Go's
// monotonic clock, CLOCK_MONOTONIC on Linux) keeps counting while the
// machine is suspended: a suspended node must not come back with a lease
// that silently got longer.
func bootClock() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return fallbackClock()
	}
	return time.Duration(ts.Nano())
}
