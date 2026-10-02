package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// W23: the binary carries systemd/ byte for byte.
func TestEmbeddedUnitsAreTheCanonicalFiles(t *testing.T) {
	for _, n := range unitNames {
		want, err := os.ReadFile(filepath.Join("systemd", n))
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := printUnit(&b, n); err != nil || !bytes.Equal(b.Bytes(), want) {
			t.Fatalf("%s: -print-unit differs (%v)", n, err)
		}
	}
	if err := printUnit(&bytes.Buffer{}, "sshd.service"); err == nil {
		t.Fatal("unknown unit printed")
	}
	var b bytes.Buffer
	if err := printUnits(&b); err != nil {
		t.Fatal(err)
	}
	got, err := parseUnits(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for n, u := range embeddedUnits() {
		if !bytes.Equal(got[n], u) {
			t.Fatalf("%s: -print-units round trip differs", n)
		}
	}
}

// The sandbox lines the W23 fixes depend on (the systemd test runs them).
func TestUnitSandbox(t *testing.T) {
	lines := func(n string) []string {
		b, _ := embeddedUnit(n)
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return out
	}
	agent, upd := lines("akari-agent.service"), lines("akari-agent-update.service")
	if !slices.Contains(agent, "ProtectProc=invisible") || slices.ContainsFunc(agent, func(l string) bool {
		return strings.HasPrefix(l, "ProcSubset")
	}) {
		t.Fatal("agent unit: ProtectProc=invisible without ProcSubset (it hides /proc/stat, meminfo, net)")
	}
	for _, l := range []string{"ReadWritePaths=/etc/systemd/system", "ProtectSystem=strict", "PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX", "ReadWritePaths=/usr/local/bin -/var/lib/private/akari-agent"} {
		if !slices.Contains(upd, l) {
			t.Fatalf("updater unit lacks %q", l)
		}
	}
	for _, u := range [][]string{agent, upd} {
		if slices.ContainsFunc(u, func(l string) bool { return strings.HasPrefix(l, "ExecPaths") }) {
			t.Fatal("no exec exceptions (W^X)")
		}
	}
}

func TestParseUnitsRefuses(t *testing.T) {
	doc := func(mod func(map[string]string)) []byte {
		u := map[string]string{}
		for n, b := range embeddedUnits() {
			u[n] = string(b)
		}
		mod(u)
		b, _ := json.Marshal(unitsDoc{Units: u})
		return b
	}
	for name, b := range map[string][]byte{
		"not json":   []byte("broken agent build"),
		"missing":    doc(func(u map[string]string) { delete(u, "akari-agent-update.path") }),
		"empty":      doc(func(u map[string]string) { u["akari-agent.service"] = "" }),
		"too large":  doc(func(u map[string]string) { u["akari-agent.service"] = strings.Repeat("x", maxUnitSize+1) }),
		"NUL":        doc(func(u map[string]string) { u["akari-agent.service"] = "[Unit]\x00" }),
		"empty list": []byte(`{"units":{}}`),
	} {
		if _, err := parseUnits(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Units a newer release adds are not installed by this updater.
	got, err := parseUnits(doc(func(u map[string]string) { u["akari-agent-new.timer"] = "[Timer]\n" }))
	if err != nil || len(got) != len(unitNames) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestStaleUnits(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("INVOCATION_ID", "")
	if s := staleUnits(dir); s != nil {
		t.Fatalf("not under systemd: %v", s)
	}
	t.Setenv("INVOCATION_ID", "abc")
	if s := staleUnits(dir); s != nil {
		t.Fatalf("no installed agent unit (development run): %v", s)
	}
	for n, b := range embeddedUnits() {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if s := staleUnits(dir); len(s) != 0 {
		t.Fatalf("current units reported stale: %v", s)
	}
	// The pre-W23 agent unit (ProcSubset=pid), and no updater trigger.
	old, _ := embeddedUnit("akari-agent.service")
	old = bytes.Replace(old, []byte("ProtectProc=invisible\n"), []byte("ProtectProc=invisible\nProcSubset=pid\n"), 1)
	if err := os.WriteFile(filepath.Join(dir, "akari-agent.service"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "akari-agent-update.path")); err != nil {
		t.Fatal(err)
	}
	if s := staleUnits(dir); !slices.Equal(s, []string{"akari-agent.service", "akari-agent-update.path"}) {
		t.Fatalf("stale %v", s)
	}
	a := &Agent{}
	if !slices.Equal(a.helloCapabilities(), agentCapabilities) || !slices.Contains(agentCapabilities, "metrics-presence") {
		t.Fatal("default capabilities")
	}
}
