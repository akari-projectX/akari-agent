package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestPair writes a certificate pair straight to the files and
// returns its serial.
func writeTestPair(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	certPEM, keyPEM, err := placeholderCert(testDomain, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.String()
}

func newFilesManager(t *testing.T) (*certManager, certFiles) {
	t.Helper()
	m := newCertManager(t.TempDir())
	f := m.files(testDomain)
	if err := os.MkdirAll(filepath.Dir(f.cert), 0o700); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func serialOf(t *testing.T, f certFiles) string {
	t.Helper()
	leaf, err := loadLeaf(f)
	if err != nil {
		t.Fatalf("loadLeaf() error: %v", err)
	}
	return leaf.SerialNumber.String()
}

// P3-18: a read error says nothing about the files' content; the stored
// pair must not be replaced by a placeholder.
func TestEnsureFilesKeepsFilesItCannotRead(t *testing.T) {
	m, f := newFilesManager(t)
	writeTestPair(t, f.cert, f.key)
	// A directory where the chain is: reading it fails with EISDIR (not
	// "missing", not "invalid"), as EIO or EMFILE would.
	if err := os.Remove(f.cert); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.cert, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ensureFiles(testDomain); err == nil {
		t.Fatal("ensureFiles() with an unreadable chain = nil error, want the read error")
	}
	if fi, err := os.Stat(f.cert); err != nil || !fi.IsDir() {
		t.Fatalf("the unreadable chain was replaced: %v %v", fi, err)
	}
}

func TestEnsureFilesWritesAPlaceholderForMissingOrDamagedFiles(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, f certFiles)
	}{
		{"missing", func(t *testing.T, f certFiles) {}},
		{"damaged chain", func(t *testing.T, f certFiles) {
			writeTestPair(t, f.cert, f.key)
			if err := os.WriteFile(f.cert, []byte("not pem"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"key of another pair", func(t *testing.T, f certFiles) {
			writeTestPair(t, f.cert, f.key)
			writeTestPair(t, filepath.Join(filepath.Dir(f.cert), "other.pem"), f.key)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, f := newFilesManager(t)
			tc.damage(t, f)
			got, err := m.ensureFiles(testDomain)
			if err != nil || !got.placeholder {
				t.Fatalf("ensureFiles() = placeholder %v, err %v; want a placeholder", got.placeholder, err)
			}
			if _, err := loadLeaf(f); err != nil {
				t.Errorf("loadLeaf() after the placeholder: %v", err)
			}
		})
	}
}

// P3-18: a crash between the key's rename and the chain's must not lose
// the new chain (it exists nowhere else) nor fall back to a placeholder.
func TestEnsureFilesFinishesAnInterruptedReplacement(t *testing.T) {
	stage := func(t *testing.T, f certFiles) (old, next string) {
		t.Helper()
		old = writeTestPair(t, f.cert, f.key)
		next = writeTestPair(t, f.cert+pendingSuffix, f.key+pendingSuffix)
		return old, next
	}
	tests := []struct {
		name       string
		prep       func(t *testing.T, f certFiles) (old, next string)
		stagedWins bool // whether the staged pair wins
	}{
		{"nothing renamed yet", stage, true},
		{"key renamed, chain not", func(t *testing.T, f certFiles) (string, string) {
			old, next := stage(t, f)
			if err := os.Rename(f.key+pendingSuffix, f.key); err != nil {
				t.Fatal(err)
			}
			return old, next
		}, true},
		{"only the key staged", func(t *testing.T, f certFiles) (string, string) {
			old, next := stage(t, f)
			if err := os.Remove(f.cert + pendingSuffix); err != nil {
				t.Fatal(err)
			}
			return old, next
		}, false},
		{"staged chain does not pair", func(t *testing.T, f certFiles) (string, string) {
			old, next := stage(t, f)
			writeTestPair(t, f.cert+pendingSuffix, filepath.Join(filepath.Dir(f.cert), "unused.key"))
			return old, next
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, f := newFilesManager(t)
			old, next := tc.prep(t, f)
			got, err := m.ensureFiles(testDomain)
			if err != nil {
				t.Fatalf("ensureFiles() error: %v", err)
			}
			want := old
			if tc.stagedWins {
				want = next
			}
			if s := serialOf(t, f); s != want {
				t.Errorf("serial after recovery = %s, want %s (old %s, staged %s)", s, want, old, next)
			}
			if !got.placeholder {
				t.Error("test pairs are placeholders; ensureFiles() reported otherwise")
			}
			for _, p := range []string{f.cert + pendingSuffix, f.key + pendingSuffix} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("%s left behind (%v)", filepath.Base(p), err)
				}
			}
		})
	}
}
