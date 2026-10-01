package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Identity files in the state directory (M1-8). Every file holds a private
// key and is written atomically with mode 0600 (temp file in the same
// directory, fsync, rename, fsync dir): a crash leaves the old or the new
// content, never a torn one.
//
//	identity.pem       current: key PEM + certificate PEM
//	identity.next.pem  renewed, not yet confirmed by the panel
//	enroll.key.pem     key generated for enrollment, before the certificate
//
// The private key is generated here (ECDSA P-256) and never leaves the
// node; nothing in this file logs key or token material.
const (
	identityFile = "identity.pem"
	nextFile     = "identity.next.pem"
	enrollFile   = "enroll.key.pem"
)

// nodeIdentity is one usable client certificate with its key.
type nodeIdentity struct {
	cert tls.Certificate
	leaf *x509.Certificate
	// source: "state" (identity.pem), "next" (identity.next.pem) or
	// "config" (v1 bootstrap file with an embedded key).
	source string
}

// identities is the agent's certificate store.
type identities struct {
	dir   string
	caPEM []byte
	pool  *x509.CertPool

	mu   sync.Mutex
	cur  *nodeIdentity // nil until enrolled
	next *nodeIdentity // pending renewal
}

// loadIdentities opens the state directory (created 0700 if missing) and
// loads what is there. Precedence for the current identity: identity.pem
// (enrolled or renewed) over the v1 key in the config file.
func loadIdentities(dir string, cfg *Config) (*identities, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(cfg.Identity.CAPEM)) {
		return nil, fmt.Errorf("cannot parse identity.ca_pem")
	}
	s := &identities{dir: dir, caPEM: []byte(cfg.Identity.CAPEM), pool: pool}
	cur, err := s.readFile(identityFile, "state")
	if err != nil {
		return nil, err
	}
	if cur == nil && cfg.Identity.KeyPEM != "" {
		cur, err = parseIdentity([]byte(cfg.Identity.CertPEM), []byte(cfg.Identity.KeyPEM), "config")
		if err != nil {
			return nil, fmt.Errorf("identity in config: %w", err)
		}
	}
	s.cur = cur
	next, err := s.readFile(nextFile, "next")
	if err != nil {
		// A broken pending renewal must not stop the agent: drop it.
		_ = os.Remove(filepath.Join(dir, nextFile))
		next = nil
	}
	s.next = next
	return s, nil
}

func (s *identities) readFile(name, source string) (*nodeIdentity, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	id, err := parseIdentity(b, b, source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return id, nil
}

func parseIdentity(certPEM, keyPEM []byte, source string) (*nodeIdentity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	cert.Leaf = leaf
	return &nodeIdentity{cert: cert, leaf: leaf, source: source}, nil
}

func (s *identities) current() *nodeIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

func (s *identities) pending() *nodeIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// newKey generates a node key: ECDSA P-256 (supported by the panel's
// rustls verifier and its CSR policy).
func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// csrFor builds the CSR the panel accepts: no subject fields that matter,
// no attributes, no extensions.
func csrFor(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// enrollKey returns the enrollment key, generating and persisting it first
// (0600) so a retry after a crash uses the same key.
func (s *identities) enrollKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(s.dir, enrollFile)
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk != nil {
			if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
				if ek, ok := k.(*ecdsa.PrivateKey); ok && ek.Curve == elliptic.P256() {
					return ek, nil
				}
			}
		}
		// Unusable: replace it.
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", enrollFile, err)
	}
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	p, err := keyPEM(k)
	if err != nil {
		return nil, err
	}
	if err := writeSecret(path, p); err != nil {
		return nil, err
	}
	return k, nil
}

// storeEnrolled persists the enrolled identity as identity.pem and removes
// the enrollment key.
func (s *identities) storeEnrolled(key *ecdsa.PrivateKey, certPEM []byte) error {
	id, blob, err := s.bundle(key, certPEM, "state")
	if err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(s.dir, identityFile), blob); err != nil {
		return err
	}
	// A renewal pending from before a re-enrollment belongs to the old,
	// now revoked lineage.
	_ = os.Remove(filepath.Join(s.dir, nextFile))
	_ = os.Remove(filepath.Join(s.dir, enrollFile))
	syncDir(s.dir)
	s.mu.Lock()
	s.cur, s.next = id, nil
	s.mu.Unlock()
	return nil
}

// storeNext persists a renewed identity as pending. The current one stays
// in use (and on disk) until the panel has accepted the new one.
func (s *identities) storeNext(key *ecdsa.PrivateKey, certPEM []byte) error {
	id, blob, err := s.bundle(key, certPEM, "next")
	if err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(s.dir, nextFile), blob); err != nil {
		return err
	}
	s.mu.Lock()
	s.next = id
	s.mu.Unlock()
	return nil
}

// promote makes the pending identity current (the panel accepted it).
func (s *identities) promote(next *nodeIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next != next {
		return nil // already promoted or replaced
	}
	if err := os.Rename(filepath.Join(s.dir, nextFile), filepath.Join(s.dir, identityFile)); err != nil {
		return fmt.Errorf("promote renewed identity: %w", err)
	}
	syncDir(s.dir)
	next.source = "state"
	s.cur, s.next = next, nil
	return nil
}

// dropNext discards a pending identity the panel refused.
func (s *identities) dropNext(next *nodeIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next != next {
		return
	}
	_ = os.Remove(filepath.Join(s.dir, nextFile))
	syncDir(s.dir)
	s.next = nil
}

// bundle checks that certPEM is a certificate for key, issued by the
// panel CA for client authentication, and returns the file content.
func (s *identities) bundle(key *ecdsa.PrivateKey, certPEM []byte, source string) (*nodeIdentity, []byte, error) {
	kp, err := keyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	id, err := parseIdentity(certPEM, kp, source)
	if err != nil {
		return nil, nil, fmt.Errorf("issued certificate: %w", err)
	}
	if _, err := id.leaf.Verify(x509.VerifyOptions{
		Roots:     s.pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, nil, fmt.Errorf("issued certificate does not verify: %w", err)
	}
	return id, append(kp, certPEM...), nil
}

// renewAt is when a certificate should be renewed: once less than a third
// of its lifetime is left.
func renewAt(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Add(-life / 3)
}

// writeSecret writes a 0600 file atomically.
func writeSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	// CreateTemp already uses 0600; make it explicit (umask-proof).
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
