package main

// Automatic node certificate (protocol 6, ConfigSnapshot.acme): the agent
// obtains and renews the certificate for the node's TLS domain itself over
// ACME (RFC 8555; Let's Encrypt by default) and serves it to the TLS
// inbounds that name the node certificate files.
//
// Store: <state dir>/tls/<domain>/{fullchain.pem,privkey.pem} (0600, dir
// 0700) and <state dir>/tls/accounts/<sha256(directory)[:16]>.key.pem (the
// ACME account key, kept across renewals). The state dir is the systemd
// StateDirectory (the agent runs as a dynamic user under
// ProtectSystem=strict: /etc is not writable for it).
//
// Challenge decision (per order, DNS-01 is not supported):
//
//	TCP 80 not an inbound port and bindable   -> HTTP-01 on :80
//	else TCP 443 not an inbound port, bindable -> TLS-ALPN-01 on :443
//	else                                       -> ERROR_PORT_BUSY
//
// After a CONNECTION/DNS-class failure the next order prefers the other
// challenge when it is available. One challenge per order keeps the failed
// validations per hour below Let's Encrypt's limit (5 per hostname) with the
// backoff below.
//
// Until the CA issued a certificate the files hold a self-signed
// placeholder for the domain, so xray always builds (other inbounds are
// never held up by ACME). Renewal (a third of the validity left, minus up to
// 1/30 of it as jitter) atomically replaces the files; xray re-reads
// certificate files every hour (transport/internet/tls setupOcspTicker; the
// inbound must not set oneTimeLoading) and serves the new certificate to
// new handshakes without touching any connection. Only the first real
// certificate after a placeholder is applied at once, by swapping the
// affected inbound handlers (CoreManager.ReloadInbounds): the other
// inbounds and their connections are untouched.
//
// Failures back off exponentially: 5 min doubling to 6 h (+0..10% jitter),
// at least 1 h after a rate-limit answer; a new domain/directory or an
// agent restart starts over.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"akari/agent/pb"
)

const (
	// LetsEncryptDirectory is the default ACME directory.
	LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

	// The node certificate files TLS inbounds name (installer drop-in:
	// LoadCredential=tls:/etc/akari-agent/tls). With ConfigSnapshot.acme set
	// these are served from the ACME store instead.
	nodeCertCredFile = "/run/credentials/akari-agent.service/tls_fullchain.pem"
	nodeKeyCredFile  = "/run/credentials/akari-agent.service/tls_privkey.pem"

	placeholderOrg = "akari-agent placeholder"

	challengeHTTP01    = "http-01"
	challengeTLSALPN01 = "tls-alpn-01"
)

// acmeOrderTimeout bounds one order (account, authorization, finalize).
const acmeOrderTimeout = 3 * time.Minute

// certFiles is where the node certificate of a domain lives.
type certFiles struct {
	cert, key string
	// placeholder: the files hold the self-signed placeholder (no CA
	// certificate yet) when they were last checked.
	placeholder bool
}

type acmeCfg struct {
	domain, directory, email string
}

// certManager obtains and renews the node certificate.
type certManager struct {
	dir   string         // <state dir>/tls
	roots *x509.CertPool // trust for the ACME directory; nil = system roots
	ua    string

	// Seams.
	httpPort, tlsPort int
	now               func() time.Time
	backoffBase       time.Duration
	backoffMax        time.Duration
	rateLimitMin      time.Duration
	// onIssued runs (on the manager's goroutine) after a CA certificate was
	// stored for a domain whose files held the placeholder.
	onIssued func(domain string)

	mu  sync.Mutex
	cfg *acmeCfg
	// tcpPorts: TCP ports the desired inbounds listen on (challenge
	// decision).
	tcpPorts portSet
	st       certState
	wake     chan struct{}
	cancel   context.CancelFunc // the order in flight, if any
}

type certState struct {
	failures      uint32
	lastErr       string
	lastKind      pb.CertStatus_ErrorKind
	lastErrAt     time.Time
	lastChallenge string
	next          time.Time
	// renewAt of the served CA certificate (jitter drawn once per cert).
	serial  string
	renewAt time.Time
	// avoid: challenge the last order failed with (connection class); the
	// next order prefers the other one.
	avoid string
	// noReplace: the last order with an ARI "replaces" was refused; order
	// without it.
	noReplace bool
}

func newCertManager(stateDir string) *certManager {
	return &certManager{
		dir:          filepath.Join(stateDir, "tls"),
		httpPort:     80,
		tlsPort:      443,
		now:          time.Now,
		backoffBase:  5 * time.Minute,
		backoffMax:   6 * time.Hour,
		rateLimitMin: time.Hour,
		wake:         make(chan struct{}, 1),
	}
}

// loadRoots reads a PEM bundle of extra roots the ACME client trusts (on
// top of the system roots). Tests and smoke (pebble) only.
func loadRoots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no PEM certificates", path)
	}
	return pool, nil
}

func normalizeAcme(c *pb.AcmeConfig) (*acmeCfg, error) {
	if c == nil || strings.TrimSpace(c.GetDomain()) == "" {
		return nil, nil
	}
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.GetDomain())), ".")
	if !validDomain(d) {
		return nil, fmt.Errorf("acme: invalid domain %q", c.GetDomain())
	}
	dir := strings.TrimSpace(c.GetDirectoryUrl())
	if dir == "" {
		dir = LetsEncryptDirectory
	}
	if !strings.HasPrefix(dir, "https://") {
		return nil, fmt.Errorf("acme: directory must be an https URL")
	}
	return &acmeCfg{domain: d, directory: dir, email: strings.TrimSpace(c.GetEmail())}, nil
}

// validDomain: a DNS name (letters, digits, '-', at least two labels), no
// wildcard, no IP literal; doubles as a path-safety check for the store.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || net.ParseIP(d) != nil || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Configure applies the Snapshot's ACME config (nil = none) and the
// inbounds it comes with. It makes sure the domain's files exist (a
// placeholder when there is no certificate yet) and returns them; ok=false
// without ACME. Synchronous and cheap (no network).
func (m *certManager) Configure(c *pb.AcmeConfig, inboundsJSON string) (certFiles, bool, error) {
	cfg, err := normalizeAcme(c)
	if err != nil {
		return certFiles{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcpPorts = inboundTCPPorts(inboundsJSON)
	changed := (cfg == nil) != (m.cfg == nil) || (cfg != nil && *cfg != *m.cfg)
	if changed {
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.cfg = cfg
		m.st = certState{}
		m.poke()
		if cfg != nil {
			slog.Info("automatic certificate configured", "domain", cfg.domain, "directory", cfg.directory)
		}
	}
	if cfg == nil {
		return certFiles{}, false, nil
	}
	f, err := m.ensureFiles(cfg.domain)
	if err != nil {
		return certFiles{}, false, err
	}
	return f, true, nil
}

func (m *certManager) poke() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *certManager) domainDir(domain string) string { return filepath.Join(m.dir, domain) }

func (m *certManager) files(domain string) certFiles {
	d := m.domainDir(domain)
	return certFiles{cert: filepath.Join(d, "fullchain.pem"), key: filepath.Join(d, "privkey.pem")}
}

// ensureFiles returns the domain's files, writing a placeholder when they
// are missing or unusable.
func (m *certManager) ensureFiles(domain string) (certFiles, error) {
	f := m.files(domain)
	if leaf, err := loadLeaf(f); err == nil {
		f.placeholder = isPlaceholder(leaf)
		return f, nil
	}
	certPEM, keyPEM, err := placeholderCert(domain, m.now())
	if err != nil {
		return f, err
	}
	if err := m.writePair(domain, certPEM, keyPEM); err != nil {
		return f, err
	}
	f.placeholder = true
	return f, nil
}

// loadLeaf parses the stored pair (must match) and returns the leaf.
func loadLeaf(f certFiles) (*x509.Certificate, error) {
	c, err := os.ReadFile(f.cert)
	if err != nil {
		return nil, err
	}
	k, err := os.ReadFile(f.key)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

func isPlaceholder(leaf *x509.Certificate) bool {
	return len(leaf.Subject.Organization) == 1 && leaf.Subject.Organization[0] == placeholderOrg &&
		bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
}

// placeholderCert: self-signed, one year, for domain.
func placeholderCert(domain string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain, Organization: []string{placeholderOrg}},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// writePair replaces the domain's key and chain, each atomically (key
// first: xray reads the chain first, and a read between the two renames
// fails to pair and keeps the previous certificate until the next read).
func (m *certManager) writePair(domain string, certPEM, keyPEM []byte) error {
	d := m.domainDir(domain)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(d, 0o700); err != nil {
		return err
	}
	f := m.files(domain)
	if err := writeSecret(f.key, keyPEM); err != nil {
		return err
	}
	return writeSecret(f.cert, certPEM)
}

// Status is the heartbeat's CertStatus (nil without ACME).
func (m *certManager) Status() *pb.CertStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil {
		return nil
	}
	s := &pb.CertStatus{
		Domain:      m.cfg.domain,
		Failures:    m.st.failures,
		LastError:   m.st.lastErr,
		ErrorKind:   m.st.lastKind,
		Challenge:   m.st.lastChallenge,
		State:       pb.CertStatus_PENDING,
		NextAttempt: unixOrZero(m.st.next),
		LastErrorAt: unixOrZero(m.st.lastErrAt),
	}
	if leaf, err := loadLeaf(m.files(m.cfg.domain)); err == nil && !isPlaceholder(leaf) {
		s.NotAfter = leaf.NotAfter.Unix()
		if m.now().Before(leaf.NotAfter) {
			s.State = pb.CertStatus_VALID
		}
	}
	if m.st.failures > 0 {
		s.State = pb.CertStatus_FAILED
	}
	return s
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// run orders certificates until ctx ends.
func (m *certManager) run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait := m.step(ctx)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-timer.C:
		}
	}
}

// step orders a certificate when one is due and returns how long to sleep.
func (m *certManager) step(ctx context.Context) time.Duration {
	m.mu.Lock()
	cfg := m.cfg
	if cfg == nil {
		m.mu.Unlock()
		return time.Hour
	}
	now := m.now()
	f := m.files(cfg.domain)
	leaf, lerr := loadLeaf(f)
	valid := lerr == nil && !isPlaceholder(leaf) && now.Before(leaf.NotAfter) && leaf.VerifyHostname(cfg.domain) == nil
	if valid {
		serial := leaf.SerialNumber.String()
		if m.st.serial != serial {
			m.st.serial = serial
			m.st.renewAt = renewTime(leaf)
		}
		if m.st.failures == 0 {
			m.st.next = m.st.renewAt
		}
	}
	due := (!valid || !now.Before(m.st.renewAt)) && !now.Before(m.st.next)
	if !due {
		wait := m.st.next.Sub(now)
		m.mu.Unlock()
		return min(max(wait, time.Second), time.Hour)
	}
	octx, cancel := context.WithTimeout(ctx, acmeOrderTimeout)
	m.cancel = cancel
	ports := m.tcpPorts
	avoid := m.st.avoid
	var replaces *x509.Certificate
	if valid && !m.st.noReplace {
		replaces = leaf
	}
	m.mu.Unlock()

	wasPlaceholder := lerr != nil || isPlaceholder(leaf)
	if valid {
		slog.Info("renewing the node certificate", "domain", cfg.domain, "not_after", leaf.NotAfter)
	} else {
		slog.Info("obtaining the node certificate", "domain", cfg.domain, "directory", cfg.directory)
	}
	certPEM, keyPEM, chal, err := m.order(octx, cfg, ports, avoid, replaces)
	cancel()

	m.mu.Lock()
	if m.cfg == nil || *m.cfg != *cfg {
		// Reconfigured while ordering: start over with the new config.
		m.mu.Unlock()
		return 0
	}
	m.cancel = nil
	m.st.lastChallenge = chal
	if err == nil {
		err = m.writePair(cfg.domain, certPEM, keyPEM)
	}
	now = m.now()
	if err != nil {
		kind := classifyACME(err)
		var p acme.Problem
		if replaces != nil && errors.As(err, &p) &&
			(p.Type == acme.ProblemTypeAlreadyReplaced || p.Type == acme.ProblemTypeMalformed) {
			m.st.noReplace = true
		}
		m.st.failures++
		m.st.lastErr = truncate(err.Error(), 512)
		m.st.lastKind = kind
		m.st.lastErrAt = now
		if kind == pb.CertStatus_ERROR_CONNECTION || kind == pb.CertStatus_ERROR_DNS {
			m.st.avoid = chal
		}
		wait := backoff(m.backoffBase, m.backoffMax, m.st.failures)
		if kind == pb.CertStatus_ERROR_RATE_LIMITED {
			wait = max(wait, m.rateLimitMin)
		}
		m.st.next = now.Add(wait)
		failures := m.st.failures
		m.mu.Unlock()
		slog.Error("node certificate order failed", "domain", cfg.domain, "challenge", chal,
			"kind", kind.String(), "failures", failures, "retry_in", wait.Round(time.Second), "error", err)
		return wait
	}
	leaf, _ = loadLeaf(f)
	m.st = certState{lastChallenge: chal}
	if leaf != nil {
		m.st.serial = leaf.SerialNumber.String()
		m.st.renewAt = renewTime(leaf)
		m.st.next = m.st.renewAt
	}
	onIssued := m.onIssued
	renew := m.st.renewAt
	m.mu.Unlock()
	if leaf != nil {
		slog.Info("node certificate stored", "domain", cfg.domain, "challenge", chal,
			"not_after", leaf.NotAfter, "renew_at", renew)
	}
	if wasPlaceholder && onIssued != nil {
		onIssued(cfg.domain)
	}
	return 0
}

// renewTime: a third of the validity left, minus up to 1/30 of the
// validity (jitter, so a fleet does not renew in lockstep).
func renewTime(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	if life <= 0 {
		return leaf.NotAfter
	}
	jitter := time.Duration(mrand.Int64N(int64(life/30) + 1))
	return leaf.NotAfter.Add(-life / 3).Add(-jitter)
}

// backoff after n consecutive failures: base * 2^(n-1), capped, +0..10%.
func backoff(base, maxWait time.Duration, n uint32) time.Duration {
	d := base
	for i := uint32(1); i < n && d < maxWait; i++ {
		d *= 2
	}
	d = min(d, maxWait)
	return d + time.Duration(mrand.Int64N(int64(d/10)+1))
}

// errPortBusy: no challenge port is usable.
type errPortBusy struct{ detail string }

func (e errPortBusy) Error() string { return e.detail }

// errCAUnreachable wraps a failure to talk to the ACME directory.
type errCAUnreachable struct{ err error }

func (e errCAUnreachable) Error() string { return "ACME directory unreachable: " + e.err.Error() }
func (e errCAUnreachable) Unwrap() error { return e.err }

func classifyACME(err error) pb.CertStatus_ErrorKind {
	var busy errPortBusy
	if errors.As(err, &busy) {
		return pb.CertStatus_ERROR_PORT_BUSY
	}
	var p acme.Problem
	if errors.As(err, &p) {
		types := []string{p.Type}
		for _, s := range p.Subproblems {
			types = append(types, s.Type)
		}
		for _, t := range types {
			switch t {
			case acme.ProblemTypeRateLimited:
				return pb.CertStatus_ERROR_RATE_LIMITED
			case acme.ProblemTypeDNS:
				return pb.CertStatus_ERROR_DNS
			case acme.ProblemTypeCAA:
				return pb.CertStatus_ERROR_CAA
			case acme.ProblemTypeConnection, acme.ProblemTypeUnauthorized,
				acme.ProblemTypeIncorrectResponse, acme.ProblemTypeTLS:
				// Some CAs (pebble) report a name that does not resolve as a
				// connection problem; Let's Encrypt uses the dns type.
				if unresolved(p) {
					return pb.CertStatus_ERROR_DNS
				}
				return pb.CertStatus_ERROR_CONNECTION
			case acme.ProblemTypeRejectedIdentifier, acme.ProblemTypeUnsupportedIdentifier:
				return pb.CertStatus_ERROR_REJECTED
			}
		}
		return pb.CertStatus_ERROR_OTHER
	}
	var u errCAUnreachable
	if errors.As(err, &u) {
		return pb.CertStatus_ERROR_CA_UNREACHABLE
	}
	return pb.CertStatus_ERROR_OTHER
}

func unresolved(p acme.Problem) bool {
	d := strings.ToLower(p.Detail)
	for _, s := range p.Subproblems {
		d += " " + strings.ToLower(s.Detail)
	}
	return strings.Contains(d, "nxdomain") || strings.Contains(d, "could not resolve") ||
		strings.Contains(d, "no valid ip addresses")
}

// warnOnly drops records below Warn (the ACME library logs every step at
// Info).
type warnOnly struct{ slog.Handler }

func (h warnOnly) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelWarn && h.Handler.Enabled(ctx, l)
}

func (h warnOnly) WithAttrs(a []slog.Attr) slog.Handler { return warnOnly{h.Handler.WithAttrs(a)} }
func (h warnOnly) WithGroup(n string) slog.Handler      { return warnOnly{h.Handler.WithGroup(n)} }

// order runs one ACME order and returns the chain and key PEM.
func (m *certManager) order(ctx context.Context, cfg *acmeCfg, ports portSet, avoid string, replaces *x509.Certificate) (certPEM, keyPEM []byte, chal string, err error) {
	solver, chal, err := m.pickSolver(ports, avoid)
	if err != nil {
		return nil, nil, "", err
	}
	defer solver.close()

	tr := http.DefaultTransport.(*http.Transport).Clone()
	if m.roots != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: m.roots, MinVersion: tls.VersionTLS12}
	}
	client := acmez.Client{
		Client: &acme.Client{
			Directory:  cfg.directory,
			HTTPClient: &http.Client{Transport: tr, Timeout: time.Minute},
			UserAgent:  m.ua,
			Logger:     slog.New(warnOnly{slog.Default().Handler()}).With("component", "acme"),
		},
		ChallengeSolvers: map[string]acmez.Solver{chal: solver},
	}
	if _, err := client.GetDirectory(ctx); err != nil {
		return nil, nil, chal, errCAUnreachable{err}
	}
	accountKey, err := m.accountKey(cfg.directory)
	if err != nil {
		return nil, nil, chal, fmt.Errorf("account key: %w", err)
	}
	acct := acme.Account{TermsOfServiceAgreed: true, PrivateKey: accountKey}
	if cfg.email != "" {
		acct.Contact = []string{"mailto:" + cfg.email}
	}
	// Same key = same account: the CA answers with the existing one.
	acct, err = client.NewAccount(ctx, acct)
	if err != nil {
		return nil, nil, chal, fmt.Errorf("account: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, chal, err
	}
	csr, err := acmez.NewCSR(certKey, []string{cfg.domain})
	if err != nil {
		return nil, nil, chal, err
	}
	params, err := acmez.OrderParametersFromCSR(acct, csr)
	if err != nil {
		return nil, nil, chal, err
	}
	// ARI (RFC 9773): a renewal names the certificate it replaces, which
	// the CA may exempt from rate limits.
	params.Replaces = replaces
	certs, err := client.ObtainCertificate(ctx, params)
	if err != nil {
		return nil, nil, chal, err
	}
	if len(certs) == 0 || len(certs[0].ChainPEM) == 0 {
		return nil, nil, chal, errors.New("the CA returned no certificate")
	}
	kder, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return nil, nil, chal, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	// Check what we store: a key pair for the domain.
	pair, err := tls.X509KeyPair(certs[0].ChainPEM, keyPEM)
	if err != nil {
		return nil, nil, chal, fmt.Errorf("issued certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(cfg.domain) != nil {
		return nil, nil, chal, fmt.Errorf("issued certificate does not cover %s", cfg.domain)
	}
	return certs[0].ChainPEM, keyPEM, chal, nil
}

// accountKey loads (or creates) the account key for a directory.
func (m *certManager) accountKey(directory string) (crypto.Signer, error) {
	sum := sha256.Sum256([]byte(directory))
	p := filepath.Join(m.dir, "accounts", hex.EncodeToString(sum[:8])+".key.pem")
	if b, err := os.ReadFile(p); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s: not PEM", p)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: not a signing key", p)
		}
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := writeSecret(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

// --- challenge solvers ------------------------------------------------------

type closingSolver interface {
	acmez.Solver
	close()
}

// pickSolver applies the decision matrix (see the file comment).
func (m *certManager) pickSolver(ports portSet, avoid string) (closingSolver, string, error) {
	order := []string{challengeHTTP01, challengeTLSALPN01}
	if avoid == challengeHTTP01 {
		order = []string{challengeTLSALPN01, challengeHTTP01}
	}
	var why []string
	for _, c := range order {
		port := m.httpPort
		if c == challengeTLSALPN01 {
			port = m.tlsPort
		}
		if ports.has(port) {
			why = append(why, fmt.Sprintf("TCP %d is used by an inbound", port))
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			why = append(why, fmt.Sprintf("TCP %d: %v", port, err))
			continue
		}
		if c == challengeHTTP01 {
			return newHTTPSolver(ln), c, nil
		}
		return newALPNSolver(ln), c, nil
	}
	return nil, "", errPortBusy{fmt.Sprintf("no ACME challenge port usable: %s (HTTP-01 needs TCP %d, TLS-ALPN-01 needs TCP %d not used by an inbound)",
		strings.Join(why, "; "), m.httpPort, m.tlsPort)}
}

// httpSolver answers HTTP-01 on its own listener (:80) for the duration of
// one order; any other request gets 404.
type httpSolver struct {
	srv  *http.Server
	mu   sync.Mutex
	chal *acme.Challenge
}

func newHTTPSolver(ln net.Listener) *httpSolver {
	s := &httpSolver{}
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return s
}

func (s *httpSolver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	c := s.chal
	s.mu.Unlock()
	if c == nil || r.Method != http.MethodGet || r.URL.Path != c.HTTP01ResourcePath() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(c.KeyAuthorization))
}

func (s *httpSolver) Present(_ context.Context, c acme.Challenge) error {
	s.mu.Lock()
	s.chal = &c
	s.mu.Unlock()
	return nil
}

func (s *httpSolver) CleanUp(context.Context, acme.Challenge) error {
	s.mu.Lock()
	s.chal = nil
	s.mu.Unlock()
	return nil
}

func (s *httpSolver) close() { _ = s.srv.Close() }

// alpnSolver answers TLS-ALPN-01 (RFC 8737) on its own listener (:443).
type alpnSolver struct {
	ln   net.Listener
	mu   sync.Mutex
	cert *tls.Certificate
	wg   sync.WaitGroup
}

func newALPNSolver(ln net.Listener) *alpnSolver {
	s := &alpnSolver{ln: ln}
	cfg := &tls.Config{
		NextProtos: []string{acmez.ACMETLS1Protocol},
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.cert == nil {
				return nil, errors.New("no challenge")
			}
			return s.cert, nil
		},
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_ = tls.Server(c, cfg).Handshake()
			}()
		}
	}()
	return s
}

func (s *alpnSolver) Present(_ context.Context, c acme.Challenge) error {
	cert, err := acmez.TLSALPN01ChallengeCert(c)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cert = cert
	s.mu.Unlock()
	return nil
}

func (s *alpnSolver) CleanUp(context.Context, acme.Challenge) error {
	s.mu.Lock()
	s.cert = nil
	s.mu.Unlock()
	return nil
}

func (s *alpnSolver) close() {
	_ = s.ln.Close()
	s.wg.Wait()
}

// --- inbound ports ------------------------------------------------------------

// portSet: TCP ports (and ranges) the inbounds listen on.
type portSet [][2]int

func (p portSet) has(port int) bool {
	for _, r := range p {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// inboundTCPPorts: the TCP ports of the inbounds JSON (xray's port forms:
// number, "443", "1000-2000", comma lists). Hysteria 2 (UDP only) does not
// occupy TCP. Unparseable values are ignored (xray refuses them anyway).
func inboundTCPPorts(inboundsJSON string) portSet {
	var ins []struct {
		Port     json.RawMessage `json:"port"`
		Protocol string          `json:"protocol"`
	}
	if json.Unmarshal([]byte(inboundsJSON), &ins) != nil {
		return nil
	}
	var out portSet
	for _, in := range ins {
		if strings.EqualFold(in.Protocol, "hysteria") {
			continue
		}
		var n int
		if json.Unmarshal(in.Port, &n) == nil {
			out = append(out, [2]int{n, n})
			continue
		}
		var s string
		if json.Unmarshal(in.Port, &s) != nil {
			continue
		}
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			lo, hi, isRange := strings.Cut(part, "-")
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			if err1 != nil {
				continue
			}
			b := a
			if isRange {
				if v, err := strconv.Atoi(strings.TrimSpace(hi)); err == nil {
					b = v
				}
			}
			out = append(out, [2]int{a, b})
		}
	}
	return out
}

// --- inbound rewrite ------------------------------------------------------------

// rewriteCertPaths points every TLS certificate entry that names the node
// certificate credential files at f, and returns the rewritten inbounds
// and the tags of the inbounds that changed. Exact (case-sensitive) key
// names, as the panel's templates write them.
func rewriteCertPaths(inbounds []json.RawMessage, f certFiles) ([]json.RawMessage, []string, error) {
	out := make([]json.RawMessage, len(inbounds))
	var tags []string
	for i, raw := range inbounds {
		out[i] = raw
		var in map[string]any
		if json.Unmarshal(raw, &in) != nil {
			continue
		}
		ss, _ := in["streamSettings"].(map[string]any)
		ts, _ := ss["tlsSettings"].(map[string]any)
		certs, _ := ts["certificates"].([]any)
		changed := false
		for _, c := range certs {
			cm, _ := c.(map[string]any)
			if cm == nil || cm["certificateFile"] != nodeCertCredFile || cm["keyFile"] != nodeKeyCredFile {
				continue
			}
			cm["certificateFile"] = f.cert
			cm["keyFile"] = f.key
			changed = true
		}
		if !changed {
			continue
		}
		b, err := json.Marshal(in)
		if err != nil {
			return nil, nil, err
		}
		out[i] = b
		if tag, _ := in["tag"].(string); tag != "" {
			tags = append(tags, tag)
		}
	}
	return out, tags, nil
}
