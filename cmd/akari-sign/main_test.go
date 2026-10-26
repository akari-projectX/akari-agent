package main

import (
	"os"
	"path/filepath"
	"testing"

	"akari/agent/release"
)

const testKey = "../../testdata/TEST-ONLY-release.key"
const testPub = "../../testdata/TEST-ONLY-release.pub"

func signArgs(t *testing.T, extra ...string) (dir string, args []string) {
	t.Helper()
	dir = t.TempDir()
	bin := filepath.Join(dir, "akari-agent-linux-amd64")
	if err := os.WriteFile(bin, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, append([]string{"sign", "-key", testKey, "-binary", bin, "-created-at", "2026-10-20T00:00:00Z"}, extra...)
}

func readManifest(t *testing.T, dir string) *release.Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "akari-agent-linux-amd64.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := release.ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSignForwardStaysSchema1(t *testing.T) {
	dir, args := signArgs(t, "-version", "v1.2.3")
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	if m := readManifest(t, dir); m.Schema != 1 || m.Rollback || m.RollbackFrom != "" || m.ExpiresAt != "" {
		t.Fatalf("%+v", m)
	}
}

func TestSignRollback(t *testing.T) {
	dir, args := signArgs(t, "-version", "v1.2.3", "-rollback", "-rollback-from", "v1.3.0")
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, dir)
	if m.Schema != 2 || !m.Rollback || m.RollbackFrom != "v1.3.0" || m.ExpiresAt != "2026-10-27T00:00:00Z" {
		t.Fatalf("default is 7 days: %+v", m)
	}
	// verify accepts it (and prints the binding).
	verify := []string{"verify", "-keys", testPub, "-manifest", filepath.Join(dir, "akari-agent-linux-amd64.manifest.json"),
		"-sig", filepath.Join(dir, "akari-agent-linux-amd64.manifest.sig")}
	if err := run(verify); err != nil {
		t.Fatal(err)
	}
	for expires, want := range map[string]string{
		"2d": "2026-10-22T00:00:00Z", "36h": "2026-10-21T12:00:00Z", "30d": "2026-11-19T00:00:00Z",
		"2026-10-21T00:00:00Z": "2026-10-21T00:00:00Z",
	} {
		dir, args := signArgs(t, "-version", "v1.2.3", "-rollback", "-rollback-from", "v1.3.0", "-expires", expires)
		if err := run(args); err != nil {
			t.Fatalf("-expires %s: %v", expires, err)
		}
		if got := readManifest(t, dir).ExpiresAt; got != want {
			t.Errorf("-expires %s = %s, want %s", expires, got, want)
		}
	}
}

func TestSignRollbackRefusals(t *testing.T) {
	for name, extra := range map[string][]string{
		"no -rollback-from":       {"-rollback"},
		"-rollback-from alone":    {"-rollback-from", "v1.3.0"},
		"from not newer":          {"-rollback", "-rollback-from", "v1.2.3"},
		"over 30 days":            {"-rollback", "-rollback-from", "v1.3.0", "-expires", "31d"},
		"over 30 days (absolute)": {"-rollback", "-rollback-from", "v1.3.0", "-expires", "2026-12-01T00:00:00Z"},
		"expires in the past":     {"-rollback", "-rollback-from", "v1.3.0", "-expires", "2026-10-19T00:00:00Z"},
		"garbage":                 {"-rollback", "-rollback-from", "v1.3.0", "-expires", "soon"},
		"zero days":               {"-rollback", "-rollback-from", "v1.3.0", "-expires", "0d"},
	} {
		dir, args := signArgs(t, append([]string{"-version", "v1.2.3"}, extra...)...)
		if err := run(args); err == nil {
			t.Errorf("%s: signed", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "akari-agent-linux-amd64.manifest.json")); err == nil {
			t.Errorf("%s: wrote a manifest", name)
		}
	}
}
