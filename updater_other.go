//go:build !linux

package main

import (
	"errors"
	"time"

	"akari/agent/release"
)

// runApplyUpdate: the privileged updater is Linux-only (systemd units).
func runApplyUpdate(string, string, string, string, []release.PublicKey, time.Duration, int) error {
	return errors.New("-apply-update is supported on Linux only")
}
