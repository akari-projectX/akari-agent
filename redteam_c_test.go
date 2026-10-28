//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Red team 2026-10 C-3: the agent owns its hand-over directory, so it can
// leave a non-empty directory under a request name. The root updater could
// not unlink it, the trigger stayed true, and the updater ran again at
// once, for ever (systemd: until the service's start limit switches the
// updater off). The name must be out of the way after a run.
func TestUpdaterClearsRequestNamesItCannotUnlink(t *testing.T) {
	for _, name := range []string{requestName, filterRequestName} {
		t.Run(name, func(t *testing.T) {
			e := newUpdaterEnv(t)
			junk := filepath.Join(e.agentDir, name)
			if err := os.MkdirAll(junk, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(junk, "x"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = e.p.run()
			if _, err := os.Lstat(junk); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s is still there after a run, the trigger would fire again: %v", name, err)
			}
		})
	}
}
