package main

// The service files of this release (W23; OpenRC since W32). systemd/ and
// openrc/ are their canonical copies: they are compiled into the binary,
// so a release always carries the units it was built and tested with.
//   - `-print-unit NAME` prints one (the panel's installer installs the
//     files of the release it installs this way: the systemd units, or on
//     Alpine the OpenRC scripts);
//   - `-print-units` prints all of them as JSON (the privileged updater
//     reads the NEW release's files from the verified binary and installs
//     those of its init system with it, updater_linux.go);
//   - the agent compares the installed copies with its own at start and
//     reports a mismatch (capability "stale-units"): the panel then asks
//     for one reinstall.
// akari-panel keeps a byte-identical copy of the systemd units
// (deploy/systemd/, the installer's fallback for releases that predate
// -print-unit): `make check-units`. The OpenRC scripts need no copy: a
// release without them cannot run under OpenRC anyway.

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"
)

//go:embed systemd/akari-agent.service systemd/akari-agent-update.service systemd/akari-agent-update.path
//go:embed openrc/akari-agent openrc/akari-agent-update
var unitFS embed.FS

// initSys is an init system the agent is installed under (-init).
type initSys struct {
	name string
	// units: the files this release carries for it and the updater may
	// replace, in install order (the agent's own first). Nothing else in
	// dir is ever touched. Names are unique across init systems.
	units []string
	// dir: where they are installed; mode: their file mode there.
	dir  string
	mode fs.FileMode
	// trigger: the updater's file; the agent refuses update offers while
	// it is missing (-updater-unit).
	trigger string
	// service: the agent's service (-update-service).
	service string
}

var (
	systemdInit = &initSys{
		name:    "systemd",
		units:   []string{"akari-agent.service", "akari-agent-update.service", "akari-agent-update.path"},
		dir:     "/etc/systemd/system",
		mode:    0o644,
		trigger: "/etc/systemd/system/akari-agent-update.path",
		service: "akari-agent.service",
	}
	// openrcInit (W32, Alpine): init scripts are executables.
	openrcInit = &initSys{
		name:    "openrc",
		units:   []string{"akari-agent", "akari-agent-update"},
		dir:     "/etc/init.d",
		mode:    0o755,
		trigger: "/etc/init.d/akari-agent-update",
		service: "akari-agent",
	}
	initSystems = []*initSys{systemdInit, openrcInit}
)

// initByName is main's -init.
func initByName(name string) (*initSys, error) {
	for _, s := range initSystems {
		if s.name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("unknown init system %q (systemd, openrc)", name)
}

// maxUnitSize bounds one unit file (the shipped ones are ~5 KiB).
const maxUnitSize = 64 << 10

// unitsDoc is the -print-units output.
type unitsDoc struct {
	Units map[string]string `json:"units"`
}

func embeddedUnit(name string) ([]byte, bool) {
	for _, s := range initSystems {
		for _, n := range s.units {
			if n == name {
				b, err := unitFS.ReadFile(s.name + "/" + name)
				return b, err == nil
			}
		}
	}
	return nil, false
}

// embeddedUnits: the files this release carries for s.
func (s *initSys) embeddedUnits() map[string][]byte {
	out := make(map[string][]byte, len(s.units))
	for _, n := range s.units {
		b, _ := embeddedUnit(n)
		out[n] = b
	}
	return out
}

func allUnitNames() []string {
	var out []string
	for _, s := range initSystems {
		out = append(out, s.units...)
	}
	return out
}

// printUnit is main's -print-unit.
func printUnit(w io.Writer, name string) error {
	b, ok := embeddedUnit(name)
	if !ok {
		return fmt.Errorf("unknown unit %q (this release carries: %v)", name, allUnitNames())
	}
	_, err := w.Write(b)
	return err
}

// printUnits is main's -print-units: every init system's files (an updater
// takes those of its own; older updaters ignore names they do not know).
func printUnits(w io.Writer) error {
	doc := unitsDoc{Units: map[string]string{}}
	for _, n := range allUnitNames() {
		b, _ := embeddedUnit(n)
		doc.Units[n] = string(b)
	}
	return json.NewEncoder(w).Encode(&doc)
}

// parseUnits reads -print-units output (of another, verified release):
// every file of s present, plausible text; other names are ignored.
func (s *initSys) parseUnits(b []byte) (map[string][]byte, error) {
	var doc unitsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("units: %w", err)
	}
	out := make(map[string][]byte, len(s.units))
	for _, n := range s.units {
		u, ok := doc.Units[n]
		switch {
		case !ok || u == "":
			return nil, fmt.Errorf("units: %s missing", n)
		case len(u) > maxUnitSize:
			return nil, fmt.Errorf("units: %s larger than %d bytes", n, maxUnitSize)
		case !utf8.ValidString(u) || bytes.IndexByte([]byte(u), 0) >= 0:
			return nil, fmt.Errorf("units: %s is not text", n)
		}
		out[n] = []byte(u)
	}
	return out, nil
}

// staleUnits: the installed files (in dir) that differ from this
// release's. Only checked when the agent runs as the installed service
// (systemd sets INVOCATION_ID; only the OpenRC script passes -init openrc)
// and dir holds the agent's own file; a missing updater file counts (the
// "updater" capability covers it too), unreadable files do not (nothing
// to report).
func (s *initSys) staleUnits(dir string) []string {
	if s == systemdInit && os.Getenv("INVOCATION_ID") == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, s.units[0])); err != nil {
		return nil
	}
	var stale []string
	for _, n := range s.units {
		want, _ := embeddedUnit(n)
		got, err := os.ReadFile(filepath.Join(dir, n))
		if errors.Is(err, os.ErrNotExist) || (err == nil && !bytes.Equal(got, want)) {
			stale = append(stale, n)
		}
	}
	return stale
}
