package main

// The systemd units of this release (W23). systemd/ is their canonical
// copy: they are compiled into the binary, so a release always carries the
// units it was built and tested with.
//   - `-print-unit NAME` prints one (the panel's installer installs the
//     units of the release it installs this way);
//   - `-print-units` prints all of them as JSON (the privileged updater
//     reads the NEW release's units from the verified binary and installs
//     them with it, updater_linux.go);
//   - the agent compares the installed copies with its own at start and
//     reports a mismatch (capability "stale-units"): the panel then asks
//     for one reinstall.
// akari-panel keeps a byte-identical copy (deploy/systemd/, the installer's
// fallback for releases that predate -print-unit): `make check-units`.

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"
)

//go:embed systemd/akari-agent.service systemd/akari-agent-update.service systemd/akari-agent-update.path
var unitFS embed.FS

// unitNames: the units a release carries and the updater may replace, in
// install order. Nothing else in the unit directory is ever touched.
var unitNames = []string{"akari-agent.service", "akari-agent-update.service", "akari-agent-update.path"}

const (
	defaultUnitDir = "/etc/systemd/system"
	// maxUnitSize bounds one unit file (the shipped ones are ~5 KiB).
	maxUnitSize = 64 << 10
)

// unitsDoc is the -print-units output.
type unitsDoc struct {
	Units map[string]string `json:"units"`
}

func embeddedUnit(name string) ([]byte, bool) {
	for _, n := range unitNames {
		if n == name {
			b, err := unitFS.ReadFile("systemd/" + name)
			return b, err == nil
		}
	}
	return nil, false
}

func embeddedUnits() map[string][]byte {
	out := make(map[string][]byte, len(unitNames))
	for _, n := range unitNames {
		b, _ := embeddedUnit(n)
		out[n] = b
	}
	return out
}

// printUnit is main's -print-unit.
func printUnit(w io.Writer, name string) error {
	b, ok := embeddedUnit(name)
	if !ok {
		return fmt.Errorf("unknown unit %q (this release carries: %v)", name, unitNames)
	}
	_, err := w.Write(b)
	return err
}

// printUnits is main's -print-units.
func printUnits(w io.Writer) error {
	doc := unitsDoc{Units: map[string]string{}}
	for n, b := range embeddedUnits() {
		doc.Units[n] = string(b)
	}
	return json.NewEncoder(w).Encode(&doc)
}

// parseUnits reads -print-units output (of another, verified release):
// every known unit present, plausible text; unknown names are ignored.
func parseUnits(b []byte) (map[string][]byte, error) {
	var doc unitsDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("units: %w", err)
	}
	out := make(map[string][]byte, len(unitNames))
	for _, n := range unitNames {
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

// staleUnits: the installed units (in dir) that differ from this release's.
// Only checked when the agent runs as the installed service (systemd sets
// INVOCATION_ID, and dir holds akari-agent.service); a missing updater
// unit counts (the "updater" capability covers it too), unreadable files
// do not (nothing to report).
func staleUnits(dir string) []string {
	if os.Getenv("INVOCATION_ID") == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, unitNames[0])); err != nil {
		return nil
	}
	var stale []string
	for _, n := range unitNames {
		want, _ := embeddedUnit(n)
		got, err := os.ReadFile(filepath.Join(dir, n))
		if errors.Is(err, os.ErrNotExist) || (err == nil && !bytes.Equal(got, want)) {
			stale = append(stale, n)
		}
	}
	return stale
}
