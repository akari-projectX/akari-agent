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
		"AKARI_FILTER_REQUEST=/var/lib/akari-agent/" + updateDirName + "/" + filterRequestName + "\n",
		"[ -e $AKARI_FILTER_REQUEST ] || [ -L $AKARI_FILTER_REQUEST ]",
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
	for _, l := range []string{"ReadWritePaths=/etc/systemd/system", "ProtectSystem=strict", "IPAddressDeny=any",
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK", "ReadWritePaths=/usr/local/bin -/var/lib/private/akari-agent"} {
		if !slices.Contains(upd, l) {
			t.Fatalf("updater unit lacks %q", l)
		}
	}
	// R44: the agent never gets CAP_NET_ADMIN; the root updater applies
	// the source allowlists in the host's network namespace.
	if slices.ContainsFunc(agent, func(l string) bool { return strings.Contains(l, "CAP_NET_ADMIN") }) {
		t.Fatal("agent unit grants CAP_NET_ADMIN")
	}
	if !slices.ContainsFunc(upd, func(l string) bool {
		return strings.HasPrefix(l, "CapabilityBoundingSet=") && strings.Contains(l, "CAP_NET_ADMIN")
	}) || slices.ContainsFunc(upd, func(l string) bool { return strings.HasPrefix(l, "PrivateNetwork") }) {
		t.Fatal("updater unit cannot apply the source allowlists")
	}
	path := lines("akari-agent-update.path")
	for _, l := range []string{"PathExists=/var/lib/private/akari-agent/update/" + requestName,
		"PathExists=/var/lib/private/akari-agent/update/" + filterRequestName} {
		if !slices.Contains(path, l) {
			t.Fatalf("trigger unit lacks %q", l)
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
