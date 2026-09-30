//go:build !linux

package main

import "time"

// bootClock: no CLOCK_BOOTTIME off Linux; the monotonic clock may not count
// suspend there (production agents run on Linux).
func bootClock() time.Duration { return fallbackClock() }
