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

// W23: the binary carries systemd/ (W32: and openrc/) byte for byte.
func TestEmbeddedUnitsAreTheCanonicalFiles(t *testing.T) {
	for _, s := range initSystems {
		for _, n := range s.units {
			want, err := os.ReadFile(filepath.Join(s.name, n))
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			if err := printUnit(&b, n); err != nil || !bytes.Equal(b.Bytes(), want) {
				t.Fatalf("%s: -print-unit differs (%v)", n, err)
			}
		}
	}
	if err := printUnit(&bytes.Buffer{}, "sshd.service"); err == nil {
		t.Fatal("unknown unit printed")
	}
	var b bytes.Buffer
	if err := printUnits(&b); err != nil {
		t.Fatal(err)
	}
	for _, s := range initSystems {
		got, err := s.parseUnits(b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(s.units) {
			t.Fatalf("%s: %d files", s.name, len(got))
		}
		for n, u := range s.embeddedUnits() {
			if !bytes.Equal(got[n], u) {
				t.Fatalf("%s: -print-units round trip differs", n)
			}
		}
	}
	// Names are unique across init systems (-print-unit takes a bare name).
	seen := map[string]bool{}
	for _, n := range allUnitNames() {
		if seen[n] {
			t.Fatalf("%s twice", n)
		}
		seen[n] = true
	}
	if s, err := initByName("openrc"); err != nil || s != openrcInit {
		t.Fatal("initByName openrc")
	}
	if _, err := initByName("runit"); err == nil {
		t.Fatal("unknown init accepted")
	}
}

// W32: what the OpenRC scripts must keep (the OpenRC test runs them).
func TestOpenRCScripts(t *testing.T) {
	agent, _ := embeddedUnit("akari-agent")
	upd, _ := embeddedUnit("akari-agent-update")
	for _, l := range []string{
		"#!/sbin/openrc-run\n",
		"supervisor=supervise-daemon\n",
		`command_user="akari-agent:akari-agent"` + "\n",
		`capabilities="^cap_net_bind_service"` + "\n",
		`no_new_privs="yes"` + "\n",
		`umask="0077"` + "\n",
		"mount -o remount,bind,noexec,nosuid,nodev",
		// acme.go reads the node certificate where systemd's
		// LoadCredential= puts it; the script copies it there.
		"AKARI_CRED=" + filepath.Dir(nodeCertCredFile) + "\n",
		`"$AKARI_CRED/tls_$f"`,
		"-init openrc -config $AKARI_CRED/bootstrap.toml -state-dir $AKARI_STATE",
		`respawn_max="${respawn_max:-0}"`,
	} {
		if !bytes.Contains(agent, []byte(l)) {
			t.Fatalf("openrc/akari-agent lacks %q", l)
		}
	}
	if filepath.Base(nodeCertCredFile) != "tls_fullchain.pem" || filepath.Base(nodeKeyCredFile) != "tls_privkey.pem" {
		t.Fatal("credential names")
	}
	for _, l := range []string{
		"#!/sbin/openrc-run\n",
		"AKARI_REQUEST=/var/lib/akari-agent/" + updateDirName + "/" + requestName + "\n",
		"/usr/local/bin/akari-agent -init openrc -apply-update /var/lib/akari-agent -updater-state /var/lib/akari-agent-update",
		`no_new_privs="yes"` + "\n",
	} {
		if !bytes.Contains(upd, []byte(l)) {
			t.Fatalf("openrc/akari-agent-update lacks %q", l)
		}
	}
	// The updater must not restart with the agent (it restarts the agent
	// itself): ordering only, no need/use.
	if bytes.Contains(upd, []byte("need akari-agent")) || bytes.Contains(upd, []byte("use akari-agent")) {
		t.Fatal("the updater depends on the agent")
	}
	if bytes.Contains(agent, []byte("need akari-agent-update")) {
		t.Fatal("the agent depends on the updater")
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
		for n, b := range systemdInit.embeddedUnits() {
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
		if _, err := systemdInit.parseUnits(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Units a newer release adds are not installed by this updater.
	got, err := systemdInit.parseUnits(doc(func(u map[string]string) { u["akari-agent-new.timer"] = "[Timer]\n" }))
	if err != nil || len(got) != len(systemdInit.units) {
		t.Fatalf("%v %v", got, err)
	}
}

func TestStaleUnits(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("INVOCATION_ID", "")
	if s := systemdInit.staleUnits(dir); s != nil {
		t.Fatalf("not under systemd: %v", s)
	}
	t.Setenv("INVOCATION_ID", "abc")
	if s := systemdInit.staleUnits(dir); s != nil {
		t.Fatalf("no installed agent unit (development run): %v", s)
	}
	for n, b := range systemdInit.embeddedUnits() {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if s := systemdInit.staleUnits(dir); len(s) != 0 {
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
	if s := systemdInit.staleUnits(dir); !slices.Equal(s, []string{"akari-agent.service", "akari-agent-update.path"}) {
		t.Fatalf("stale %v", s)
	}
	a := &Agent{}
	if !slices.Equal(a.helloCapabilities(), agentCapabilities) || !slices.Contains(agentCapabilities, "metrics-presence") {
		t.Fatal("default capabilities")
	}
}

func TestStaleUnitsOpenRC(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("INVOCATION_ID", "") // not systemd: -init openrc is the signal
	if s := openrcInit.staleUnits(dir); s != nil {
		t.Fatalf("no installed agent script (development run): %v", s)
	}
	for n, b := range openrcInit.embeddedUnits() {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if s := openrcInit.staleUnits(dir); len(s) != 0 {
		t.Fatalf("current scripts reported stale: %v", s)
	}
	if err := os.WriteFile(filepath.Join(dir, "akari-agent"), []byte("#!/sbin/openrc-run\n# edited\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "akari-agent-update")); err != nil {
		t.Fatal(err)
	}
	if s := openrcInit.staleUnits(dir); !slices.Equal(s, []string{"akari-agent", "akari-agent-update"}) {
		t.Fatalf("stale %v", s)
	}
	// systemd units in the same directory are not looked at.
	if s := systemdInit.staleUnits(dir); s != nil {
		t.Fatalf("systemd: %v", s)
	}
}
