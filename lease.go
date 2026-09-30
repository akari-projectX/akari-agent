package main

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// defaultLease applies to a grant of 0 seconds.
	defaultLease = 24 * time.Hour
	// minLease is the floor for pushed durations: a buggy or hostile value
	// must not make the node flap.
	minLease = time.Hour
	// maxLease bounds pushed durations (overflow and "forever" guard).
	maxLease = 30 * 24 * time.Hour
)

var processStart = time.Now()

func fallbackClock() time.Duration { return time.Since(processStart) }

// clampLease maps a pushed duration to the one the agent enforces.
func clampLease(seconds uint64) time.Duration {
	if seconds == 0 {
		return defaultLease
	}
	if seconds > uint64(maxLease/time.Second) {
		return maxLease
	}
	d := time.Duration(seconds) * time.Second
	if d < minLease {
		return minLease
	}
	return d
}

// leaseState is the fail-closed lease: while armed, xray may only run until
// expiresAt on the boot clock. It is armed by the first LeaseGrant (a panel
// that predates leases never arms it — rollout is agents first) and renewed
// by every later one.
type leaseState struct {
	mu        sync.Mutex
	now       func() time.Duration
	armed     bool
	duration  time.Duration
	expiresAt time.Duration
	warned    int // highest warning level logged for this grant (50, 90)
}

func newLeaseState(now func() time.Duration) *leaseState {
	return &leaseState{now: now}
}

func (l *leaseState) grant(seconds uint64) time.Duration {
	d := clampLease(seconds)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.armed = true
	l.duration = d
	l.expiresAt = l.now() + d
	l.warned = 0
	return d
}

// remaining returns the time left and whether a lease is armed.
func (l *leaseState) remaining() (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.armed {
		return 0, false
	}
	left := l.expiresAt - l.now()
	if left < 0 {
		left = 0
	}
	return left, true
}

// check logs the 50%/90% warnings and reports whether the lease is expired.
func (l *leaseState) check() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.armed {
		return false
	}
	now := l.now()
	left := l.expiresAt - now
	if left <= 0 {
		return true
	}
	used := 100 - int(left*100/l.duration)
	for _, level := range []int{50, 90} {
		if used >= level && l.warned < level {
			l.warned = level
			slog.Warn("panel lease running out: no confirmation from the panel's database",
				"used_percent", level, "remaining", left.Round(time.Second))
		}
	}
	return false
}
