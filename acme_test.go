package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"akari/agent/pb"
)

const testDomain = "node.akari.test"

// newTestCertManager: a manager in a temp state dir that trusts ca and
// answers challenges on free local ports (the CA validates those ports).
func newTestCertManager(t *testing.T, validity uint64) (*certManager, *pebbleCA) {
	t.Helper()
	hp, tp := freePort(t), freePort(t)
	ca := newPebbleCA(t, hp, tp, validity)
	ca.dns.set(testDomain, "127.0.0.1")
	m := newCertManager(t.TempDir())
	m.roots = ca.apiRoots
	m.httpPort, m.tlsPort = hp, tp
	m.ua = "akari-agent/test"
	return m, ca
}

func acmeCfgFor(ca *pebbleCA) *pb.AcmeConfig {
	return &pb.AcmeConfig{Domain: testDomain, DirectoryUrl: ca.directory, Email: "ops@akari.test"}
}

func leafOf(t *testing.T, f certFiles) *x509.Certificate {
	t.Helper()
	leaf, err := loadLeaf(f)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func verifyIssued(t *testing.T, ca *pebbleCA, f certFiles) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(f.cert)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for rest := b; ; {
		var c *x509.Certificate
		c, rest, err = nextCert(rest)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			break
		}
		chain = append(chain, c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: testDomain, Roots: ca.issuerRoots, Intermediates: inter}); err != nil {
		t.Fatalf("issued chain does not verify for %s: %v", testDomain, err)
	}
	return chain[0]
}

func TestACMEObtainHTTP01(t *testing.T) {
	m, ca := newTestCertManager(t, 0)
	f, ok, err := m.Configure(acmeCfgFor(ca), `[{"tag":"x","port":443,"protocol":"vless"}]`)
	if err != nil || !ok {
		t.Fatalf("configure: %v %v", ok, err)
	}
	if !f.placeholder || !isPlaceholder(leafOf(t, f)) {
		t.Fatal("before the first order the files must hold the placeholder")
	}
	if st := m.Status(); st.State != pb.CertStatus_PENDING || st.Domain != testDomain || st.NotAfter != 0 {
		t.Fatalf("status before order: %+v", st)
	}
	var issued atomic.Int32
	m.onIssued = func(d string) {
		if d == testDomain {
			issued.Add(1)
		}
	}
	m.step(context.Background())
	st := m.Status()
	if st.State != pb.CertStatus_VALID || st.Challenge != challengeHTTP01 || st.LastError != "" || st.NotAfter == 0 {
		t.Fatalf("status after order: %+v", st)
	}
	if issued.Load() != 1 {
		t.Fatal("onIssued must fire once after the placeholder is replaced")
	}
	leaf := verifyIssued(t, ca, f)
	if st.NextAttempt <= time.Now().Unix() || st.NextAttempt >= leaf.NotAfter.Unix() {
		t.Fatalf("next attempt %d outside (now, not_after %d)", st.NextAttempt, leaf.NotAfter.Unix())
	}
	for _, p := range []string{f.cert, f.key, filepath.Dir(f.cert)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s mode %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	accounts, _ := filepath.Glob(filepath.Join(m.dir, "accounts", "*.key.pem"))
	if len(accounts) != 1 {
		t.Fatalf("account key not persisted: %v", accounts)
	}
	key1, _ := os.ReadFile(accounts[0])

	// A valid certificate is not ordered again (and the account key stays).
	m.step(context.Background())
	if leafOf(t, f).SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("a valid certificate must not be re-ordered")
	}
	// A new process (same state dir) keeps the certificate and the account.
	m2 := newCertManager(filepath.Dir(m.dir))
	m2.roots, m2.httpPort, m2.tlsPort = m.roots, m.httpPort, m.tlsPort
	f2, _, err := m2.Configure(acmeCfgFor(ca), "[]")
	if err != nil || f2.placeholder {
		t.Fatalf("restart must keep the issued certificate: %v %v", f2.placeholder, err)
	}
	if st := m2.Status(); st.State != pb.CertStatus_VALID {
		t.Fatalf("status after restart: %+v", st)
	}
	key2, _ := os.ReadFile(accounts[0])
	if string(key1) != string(key2) {
		t.Fatal("account key changed")
	}
}

func TestACMETLSALPN01WhenPort80IsAnInbound(t *testing.T) {
	m, ca := newTestCertManager(t, 0)
	inb := fmt.Sprintf(`[{"tag":"vm","port":%d,"protocol":"vmess"},{"tag":"hy","port":%d,"protocol":"hysteria"}]`, m.httpPort, m.tlsPort)
	f, _, err := m.Configure(acmeCfgFor(ca), inb)
	if err != nil {
		t.Fatal(err)
	}
	m.step(context.Background())
	st := m.Status()
	if st.State != pb.CertStatus_VALID || st.Challenge != challengeTLSALPN01 {
		t.Fatalf("status: %+v", st)
	}
	verifyIssued(t, ca, f)
}

func TestACMEHTTP01WhenPort443IsAnInboundAndPort80Busy(t *testing.T) {
	// 80 busy (held by someone else), 443 an inbound -> port busy, no order.
	m, ca := newTestCertManager(t, 0)
	busy, err := net.Listen("tcp", fmt.Sprintf(":%d", m.httpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, _, err := m.Configure(acmeCfgFor(ca), fmt.Sprintf(`[{"tag":"t","port":"%d","protocol":"trojan"}]`, m.tlsPort)); err != nil {
		t.Fatal(err)
	}
	wait := m.step(context.Background())
	st := m.Status()
	if st.State != pb.CertStatus_FAILED || st.ErrorKind != pb.CertStatus_ERROR_PORT_BUSY || st.Failures != 1 {
		t.Fatalf("status: %+v", st)
	}
	if !strings.Contains(st.LastError, "used by an inbound") {
		t.Fatalf("error should say why: %s", st.LastError)
	}
	if wait < m.backoffBase || wait > m.backoffBase*11/10+time.Second {
		t.Fatalf("first retry in %v, want ~%v", wait, m.backoffBase)
	}
	// Port freed: the next due step succeeds and clears the failure.
	busy.Close()
	m.mu.Lock()
	m.st.next = time.Time{}
	m.mu.Unlock()
	m.step(context.Background())
	if st := m.Status(); st.State != pb.CertStatus_VALID || st.Failures != 0 || st.LastError != "" {
		t.Fatalf("after freeing the port: %+v", st)
	}
}

func TestACMEFailuresAreClassifiedAndBackOff(t *testing.T) {
	m, ca := newTestCertManager(t, 0)

	// The domain does not resolve.
	cfg := acmeCfgFor(ca)
	cfg.Domain = "missing.akari.test"
	if _, _, err := m.Configure(cfg, "[]"); err != nil {
		t.Fatal(err)
	}
	m.step(context.Background())
	if st := m.Status(); st.State != pb.CertStatus_FAILED || st.ErrorKind != pb.CertStatus_ERROR_DNS {
		t.Fatalf("unresolvable domain: %+v", st)
	}

	// The domain points elsewhere: the CA reaches nothing (the agent
	// answers on other ports than the ones the CA validates).
	ca.dns.set("elsewhere.akari.test", "127.0.0.1")
	m.httpPort, m.tlsPort = freePort(t), freePort(t)
	cfg.Domain = "elsewhere.akari.test"
	if _, _, err := m.Configure(cfg, "[]"); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Failures != 0 {
		t.Fatal("a new domain starts over")
	}
	w1 := m.step(context.Background())
	st := m.Status()
	if st.State != pb.CertStatus_FAILED || st.ErrorKind != pb.CertStatus_ERROR_CONNECTION || st.Challenge != challengeHTTP01 {
		t.Fatalf("wrong address: %+v", st)
	}
	// The next order tries the other challenge; failures double the wait.
	m.mu.Lock()
	m.st.next = time.Time{}
	m.mu.Unlock()
	w2 := m.step(context.Background())
	st = m.Status()
	if st.Challenge != challengeTLSALPN01 || st.Failures != 2 {
		t.Fatalf("second order: %+v", st)
	}
	if w2 < 2*m.backoffBase || w1 >= w2 {
		t.Fatalf("backoff %v then %v", w1, w2)
	}
	// Not due yet: no order (the step only sleeps).
	if w := m.step(context.Background()); w <= 0 || m.Status().Failures != 2 {
		t.Fatalf("must not order before the backoff ends (%v)", w)
	}
}

func TestACMERenewalReplacesFilesAtomically(t *testing.T) {
	m, ca := newTestCertManager(t, 3600)
	f, _, _ := m.Configure(acmeCfgFor(ca), "[]")
	m.step(context.Background())
	first := verifyIssued(t, ca, f)
	if first.NotAfter.Sub(first.NotBefore) > 2*time.Hour {
		t.Fatalf("validity %v", first.NotAfter.Sub(first.NotBefore))
	}
	var issued atomic.Int32
	m.onIssued = func(string) { issued.Add(1) }
	// Not due before 2/3 of the lifetime (minus jitter).
	m.now = func() time.Time {
		return first.NotBefore.Add(time.Duration(float64(first.NotAfter.Sub(first.NotBefore)) * 0.5))
	}
	m.step(context.Background())
	if leafOf(t, f).SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed too early")
	}
	m.now = func() time.Time { return first.NotAfter.Add(-10 * time.Minute) }
	m.step(context.Background())
	second := verifyIssued(t, ca, f)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed with a third of the lifetime left")
	}
	if issued.Load() != 0 {
		t.Fatal("a renewal must not swap inbounds (xray re-reads the files)")
	}
	if st := m.Status(); st.State != pb.CertStatus_VALID || st.NotAfter != second.NotAfter.Unix() {
		t.Fatalf("status after renewal: %+v", st)
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(filepath.Dir(f.cert))
	if len(ents) != 2 {
		t.Fatalf("store has %d entries", len(ents))
	}
}

func TestACMEReconfigureAndDisable(t *testing.T) {
	m := newCertManager(t.TempDir())
	if _, ok, err := m.Configure(nil, "[]"); ok || err != nil || m.Status() != nil {
		t.Fatal("no ACME config: nothing to do, no status")
	}
	if _, _, err := m.Configure(&pb.AcmeConfig{Domain: "../etc"}, "[]"); err == nil {
		t.Fatal("bad domain accepted")
	}
	if _, _, err := m.Configure(&pb.AcmeConfig{Domain: "a.example.com", DirectoryUrl: "http://ca"}, "[]"); err == nil {
		t.Fatal("non-https directory accepted")
	}
	f, ok, err := m.Configure(&pb.AcmeConfig{Domain: "A.Example.COM."}, "[]")
	if err != nil || !ok || !strings.HasSuffix(filepath.Dir(f.cert), "a.example.com") {
		t.Fatalf("normalized domain: %v %v %s", ok, err, f.cert)
	}
	if m.cfg.directory != LetsEncryptDirectory {
		t.Fatal("default directory must be Let's Encrypt")
	}
	if _, ok, _ := m.Configure(nil, "[]"); ok || m.Status() != nil {
		t.Fatal("disabling must stop reporting")
	}
}

func TestInboundTCPPorts(t *testing.T) {
	p := inboundTCPPorts(`[{"port":443,"protocol":"vless"},{"port":"8080","protocol":"vmess"},
		{"port":"1000-2000,3000","protocol":"trojan"},{"port":80,"protocol":"hysteria"},{"port":"env:X"}]`)
	for _, c := range []struct {
		port int
		want bool
	}{{443, true}, {8080, true}, {1500, true}, {3000, true}, {80, false}, {2001, false}} {
		if p.has(c.port) != c.want {
			t.Fatalf("port %d: %v", c.port, !c.want)
		}
	}
	if inboundTCPPorts("not json") != nil {
		t.Fatal("bad json")
	}
}

func TestRewriteCertPaths(t *testing.T) {
	in := []json.RawMessage{
		json.RawMessage(`{"tag":"a","streamSettings":{"security":"tls","tlsSettings":{"serverName":"x","certificates":[{"certificateFile":"` + nodeCertCredFile + `","keyFile":"` + nodeKeyCredFile + `"}]}}}`),
		json.RawMessage(`{"tag":"b","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/own/c.pem","keyFile":"/own/k.pem"}]}}}`),
		json.RawMessage(`{"tag":"c","streamSettings":{"security":"reality"}}`),
	}
	out, tags, err := rewriteCertPaths(in, certFiles{cert: "/s/tls/d/fullchain.pem", key: "/s/tls/d/privkey.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0] != "a" {
		t.Fatalf("tags %v", tags)
	}
	if !strings.Contains(string(out[0]), `"/s/tls/d/fullchain.pem"`) || !strings.Contains(string(out[0]), `"/s/tls/d/privkey.pem"`) ||
		strings.Contains(string(out[0]), "credentials") || !strings.Contains(string(out[0]), `"serverName":"x"`) {
		t.Fatalf("rewritten: %s", out[0])
	}
	if string(out[1]) != string(in[1]) || string(out[2]) != string(in[2]) {
		t.Fatal("other inbounds must stay byte-identical")
	}
}

func TestClassifyACME(t *testing.T) {
	cases := []struct {
		err  error
		want pb.CertStatus_ErrorKind
	}{
		{acme.Problem{Type: acme.ProblemTypeRateLimited}, pb.CertStatus_ERROR_RATE_LIMITED},
		{fmt.Errorf("[x] %w", acme.Problem{Type: acme.ProblemTypeDNS}), pb.CertStatus_ERROR_DNS},
		{acme.Problem{Type: acme.ProblemTypeCompound, Subproblems: []acme.Subproblem{{Problem: acme.Problem{Type: acme.ProblemTypeCAA}}}}, pb.CertStatus_ERROR_CAA},
		{acme.Problem{Type: acme.ProblemTypeUnauthorized}, pb.CertStatus_ERROR_CONNECTION},
		{acme.Problem{Type: acme.ProblemTypeRejectedIdentifier}, pb.CertStatus_ERROR_REJECTED},
		{acme.Problem{Type: acme.ProblemTypeServerInternal}, pb.CertStatus_ERROR_OTHER},
		{errPortBusy{"x"}, pb.CertStatus_ERROR_PORT_BUSY},
		{errCAUnreachable{errors.New("dial")}, pb.CertStatus_ERROR_CA_UNREACHABLE},
		{errors.New("x"), pb.CertStatus_ERROR_OTHER},
	}
	for _, c := range cases {
		if got := classifyACME(c.err); got != c.want {
			t.Fatalf("%v: %v, want %v", c.err, got, c.want)
		}
	}
}

func TestACMERateLimitWaitsAtLeastAnHour(t *testing.T) {
	// The CA's directory is unreachable here; force the rate-limit class
	// through the classifier path used by step.
	if d := backoff(5*time.Minute, 6*time.Hour, 1); d < 5*time.Minute || d > 5*time.Minute*11/10+time.Second {
		t.Fatalf("backoff(1) = %v", d)
	}
	if d := backoff(5*time.Minute, 6*time.Hour, 30); d < 6*time.Hour || d > 6*time.Hour*11/10+time.Second {
		t.Fatalf("backoff cap = %v", d)
	}
	// Five failed validations per hour is Let's Encrypt's limit per
	// hostname; one challenge per order and this backoff stay below it.
	var at time.Duration
	n := 1
	for i := uint32(1); ; i++ {
		at += backoff(5*time.Minute, 6*time.Hour, i)
		if at >= time.Hour {
			break
		}
		n++
	}
	if n >= 5 {
		t.Fatalf("%d orders in the first hour", n)
	}
}

func TestACMEDirectoryUnreachable(t *testing.T) {
	m := newCertManager(t.TempDir())
	m.httpPort, m.tlsPort = freePort(t), freePort(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if _, _, err := m.Configure(&pb.AcmeConfig{Domain: testDomain, DirectoryUrl: "https://" + addr + "/dir"}, "[]"); err != nil {
		t.Fatal(err)
	}
	m.step(context.Background())
	if st := m.Status(); st.ErrorKind != pb.CertStatus_ERROR_CA_UNREACHABLE || st.State != pb.CertStatus_FAILED {
		t.Fatalf("status %+v", st)
	}
}

func TestRenewTimeJitter(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
	for i := 0; i < 50; i++ {
		r := renewTime(leaf)
		lo := leaf.NotAfter.Add(-30*24*time.Hour - 3*24*time.Hour)
		hi := leaf.NotAfter.Add(-30 * 24 * time.Hour)
		if r.Before(lo) || r.After(hi) {
			t.Fatalf("renew at %v outside [%v, %v]", r, lo, hi)
		}
	}
}

// nextCert parses the next CERTIFICATE block of a PEM bundle (nil at the
// end).
func nextCert(b []byte) (*x509.Certificate, []byte, error) {
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			return nil, nil, nil
		}
		if blk.Type != "CERTIFICATE" {
			b = rest
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		return c, rest, err
	}
}

func tlsInbound(t *testing.T) string {
	port, other := freePort(t), freePort(t)
	return fmt.Sprintf(`[{"tag":"t","listen":"127.0.0.1","port":%d,"protocol":"trojan","settings":{"clients":[]},`+
		`"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":%q,"certificates":[{"certificateFile":%q,"keyFile":%q}]}}},`+
		`{"tag":"v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`,
		port, testDomain, nodeCertCredFile, nodeKeyCredFile, other)
}

// A Snapshot with acme builds even before any certificate exists (the
// placeholder), the state hash covers the panel's JSON verbatim, and the
// heartbeat reports the certificate. Without acme the inbound reads the
// credential files as before (missing here: the apply fails, as today).
func TestSnapshotWithACMEUsesTheStore(t *testing.T) {
	a := NewAgent(&Config{}, "test", nil)
	defer a.core.Teardown()
	a.certs = newCertManager(t.TempDir())
	ctx := context.Background()
	inb := tlsInbound(t)

	out, send := collect()
	msg := snapshotMsg(2, 1, inb)
	msg.GetSnapshot().Acme = &pb.AcmeConfig{Domain: testDomain}
	if err := a.handleDown(ctx, 0, send, msg); err != nil {
		t.Fatal(err)
	}
	if ack := lastAck(t, *out); !ack.Ok {
		t.Fatalf("snapshot with acme: %v", ack)
	}
	if !a.core.ServesPlaceholder() {
		t.Fatal("must serve the placeholder until the CA issues")
	}
	if got := a.core.inboundsJSON; got != inb {
		t.Fatal("the state hash must bind the panel's inbounds verbatim")
	}
	if st := a.certStatus(); st == nil || st.Domain != testDomain || st.State != pb.CertStatus_PENDING {
		t.Fatalf("heartbeat cert status %+v", st)
	}

	*out = nil
	if err := a.handleDown(ctx, 0, send, snapshotMsg(3, 1, inb)); err != nil {
		t.Fatal(err)
	}
	if ack := lastAck(t, *out); ack.Ok || !strings.Contains(ack.Error, "tls_fullchain.pem") {
		t.Fatalf("without acme the credential files are read: %v", ack)
	}
	if a.certStatus() != nil {
		t.Fatal("no acme, no status")
	}
}

// If the inbound swap fails, the agent claims nothing so the panel sends a
// Snapshot (the rebuild then reads the new certificate).
func TestCertSwapFailureAsksForSnapshot(t *testing.T) {
	a := NewAgent(&Config{}, "test", nil)
	defer a.core.Teardown()
	a.certs = newCertManager(t.TempDir())
	out, send := collect()
	msg := snapshotMsg(4, 2, tlsInbound(t))
	msg.GetSnapshot().Acme = &pb.AcmeConfig{Domain: testDomain}
	if err := a.handleDown(context.Background(), 0, send, msg); err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	gen := a.attachStream(send, nil, cancel, false)
	defer a.detachStream(gen)
	a.core.mu.Lock()
	a.core.acmeTags = []string{"no-such-tag"}
	a.core.mu.Unlock()
	*out = nil
	a.onCertIssued()
	if c, u := a.versions(); c != 0 || u != 0 || !a.isDirty() {
		t.Fatalf("held %d/%d dirty=%v", c, u, a.isDirty())
	}
	if len(*out) != 1 || (*out)[0].GetHello().GetConfigVersion() != 0 {
		t.Fatalf("expected a Hello (0,0): %v", *out)
	}
}
