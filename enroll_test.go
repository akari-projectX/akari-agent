package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"akari/agent/pb"
)

// testCA mints certificates like the panel does.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

var serialSeq atomic.Int64

// issue signs a ClientAuth certificate for pub valid [notBefore, notBefore+life].
func (c *testCA) issue(t *testing.T, pub crypto.PublicKey, notBefore time.Time, life time.Duration) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x4000 + serialSeq.Add(1)),
		Subject:      pkix.Name{CommonName: "agent-test"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(life),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (c *testCA) serverTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "akari"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (c *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// enrolledIDs: a state dir holding an enrolled identity (90 days).
func (c *testCA) enrolledIDs(t *testing.T) *identities {
	t.Helper()
	ids, err := loadIdentities(t.TempDir(), &Config{Identity: IdentityConfig{CAPEM: c.pem}})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := newKey()
	if err := ids.storeEnrolled(key, c.issue(t, &key.PublicKey, time.Now().Add(-time.Minute), 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return ids
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// Keys are generated locally, persisted 0600, and the identity files
// follow the documented lifecycle.
func TestIdentityFilesLifecycle(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cfg := &Config{Identity: IdentityConfig{CAPEM: ca.pem}}
	ids, err := loadIdentities(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ids.current() != nil {
		t.Fatal("empty state dir has no identity")
	}
	k1, err := ids.enrollKey()
	if err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, enrollFile)); m != 0o600 {
		t.Fatalf("enroll key mode %o", m)
	}
	k2, _ := ids.enrollKey()
	if !k1.Equal(k2) {
		t.Fatal("the enrollment key must survive a retry")
	}
	if err := ids.storeEnrolled(k1, ca.issue(t, &k1.PublicKey, time.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, identityFile)); m != 0o600 {
		t.Fatalf("identity mode %o", m)
	}
	if _, err := os.Stat(filepath.Join(dir, enrollFile)); !os.IsNotExist(err) {
		t.Fatal("enrollment key left behind")
	}
	// Foreign CA / wrong key: refused, nothing stored.
	other := newTestCA(t)
	k3, _ := newKey()
	if err := ids.storeNext(k3, other.issue(t, &k3.PublicKey, time.Now(), time.Hour)); err == nil {
		t.Fatal("accepted a certificate from another CA")
	}
	if err := ids.storeNext(k3, ca.issue(t, &k1.PublicKey, time.Now(), time.Hour)); err == nil {
		t.Fatal("accepted a certificate for another key")
	}
	if ids.pending() != nil {
		t.Fatal("refused certificate became pending")
	}
	if err := ids.storeNext(k3, ca.issue(t, &k3.PublicKey, time.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, filepath.Join(dir, nextFile)); m != 0o600 {
		t.Fatalf("next mode %o", m)
	}
	// A restart sees both; the current one is unchanged.
	re, err := loadIdentities(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if re.current() == nil || re.pending() == nil || !re.current().cert.PrivateKey.(*ecdsa.PrivateKey).Equal(k1) {
		t.Fatal("reload lost the current or pending identity")
	}
	next := re.pending()
	if err := re.promote(next); err != nil {
		t.Fatal(err)
	}
	if re.pending() != nil || re.current() != next {
		t.Fatal("promote")
	}
	if _, err := os.Stat(filepath.Join(dir, nextFile)); !os.IsNotExist(err) {
		t.Fatal("next file left after promote")
	}
	if m := mode(t, filepath.Join(dir, identityFile)); m != 0o600 {
		t.Fatalf("promoted identity mode %o", m)
	}
	// dropNext removes a refused renewal.
	k4, _ := newKey()
	if err := re.storeNext(k4, ca.issue(t, &k4.PublicKey, time.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	re.dropNext(re.pending())
	if re.pending() != nil {
		t.Fatal("dropNext")
	}
	if _, err := os.Stat(filepath.Join(dir, nextFile)); !os.IsNotExist(err) {
		t.Fatal("next file left after drop")
	}
	// No temp files anywhere.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	// A corrupt pending renewal is dropped, not fatal.
	_ = os.WriteFile(filepath.Join(dir, nextFile), []byte("junk"), 0o600)
	re2, err := loadIdentities(dir, cfg)
	if err != nil || re2.pending() != nil || re2.current() == nil {
		t.Fatalf("corrupt next: %v", err)
	}
}

// v1 bootstrap files (panel-generated key in the config) keep working; the
// state dir wins once it holds an identity (after the first renewal).
func TestV1ConfigIdentity(t *testing.T) {
	ca := newTestCA(t)
	key, _ := newKey()
	kp, _ := keyPEM(key)
	cfg := &Config{Identity: IdentityConfig{
		CAPEM: ca.pem, CertPEM: string(ca.issue(t, &key.PublicKey, time.Now(), time.Hour)), KeyPEM: string(kp),
	}}
	dir := t.TempDir()
	ids, err := loadIdentities(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ids.current() == nil || ids.current().source != "config" {
		t.Fatal("v1 identity not used")
	}
	k2, _ := newKey()
	if err := ids.storeNext(k2, ca.issue(t, &k2.PublicKey, time.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := ids.promote(ids.pending()); err != nil {
		t.Fatal(err)
	}
	re, _ := loadIdentities(dir, cfg)
	if re.current().source != "state" || !re.current().cert.PrivateKey.(*ecdsa.PrivateKey).Equal(k2) {
		t.Fatal("after renewal the locally generated key must win over the config's")
	}
}

func TestCSRShapeAndRenewAt(t *testing.T) {
	key, _ := newKey()
	der, err := csrFor(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatal("CSR must be P-256 / ecdsa-with-SHA256")
	}
	if len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.Attributes) != 0 {
		t.Fatal("CSR must carry no extensions or attributes")
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: t0, NotAfter: t0.Add(90 * 24 * time.Hour)}
	if got := renewAt(leaf); !got.Equal(t0.Add(60 * 24 * time.Hour)) {
		t.Fatalf("renewAt %v", got)
	}
}

func TestConfigVersions(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.toml")
		_ = os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	if _, err := LoadConfig(write("panel_addr = \"x:1\"\nenrollment_token = \"t\"\n[identity]\nca_pem = \"c\"\n")); err != nil {
		t.Fatalf("v2: %v", err)
	}
	if _, err := LoadConfig(write("panel_addr = \"x:1\"\n[identity]\nca_pem = \"c\"\ncert_pem = \"a\"\n")); err == nil {
		t.Fatal("cert without key accepted")
	}
	if _, err := LoadConfig(write("panel_addr = \"x:1\"\nbogus = 1\n[identity]\nca_pem = \"c\"\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := LoadConfig(write("panel_addr = \"x:1\"\n")); err == nil {
		t.Fatal("missing CA accepted")
	}
}

// tlsPanel is a fake panel over real TLS with optional client
// certificates, like the real one: Enroll without, the channel with.
type tlsPanel struct {
	pb.UnimplementedAgentChannelServer
	pb.UnimplementedAgentEnrollmentServer
	t     *testing.T
	ca    *testCA
	token string
	life  time.Duration

	mu       sync.Mutex
	enrolls  int
	renews   int
	streams  []string // client cert serials, in order
	refuse   map[string]bool
	badRenew bool // answer Renew with a certificate for another key
	// refuseIssued: certificates issued by Renew from now on are refused
	// on the channel.
	refuseIssued bool
}

func peerSerial(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return ""
	}
	return ti.State.PeerCertificates[0].SerialNumber.Text(16)
}

func (f *tlsPanel) sign(der []byte) (*pb.IssuedCertificate, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "bad csr")
	}
	pub := csr.PublicKey
	if f.badRenew {
		k, _ := newKey()
		pub = &k.PublicKey
	}
	certPEM := f.ca.issue(f.t, pub, time.Now().Add(-time.Second), f.life)
	if f.refuseIssued {
		blk, _ := pem.Decode(certPEM)
		c, _ := x509.ParseCertificate(blk.Bytes)
		f.refuse[c.SerialNumber.Text(16)] = true
	}
	return &pb.IssuedCertificate{CertPem: string(certPEM), CaPem: f.ca.pem}, nil
}

func (f *tlsPanel) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if peerSerial(ctx) != "" {
		return nil, status.Error(codes.InvalidArgument, "unexpected client cert")
	}
	if req.Token != f.token {
		return nil, status.Error(codes.PermissionDenied, "enrollment refused")
	}
	f.enrolls++
	f.token = "" // single use
	return f.sign(req.CsrDer)
}

func (f *tlsPanel) Renew(ctx context.Context, req *pb.RenewRequest) (*pb.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if peerSerial(ctx) == "" {
		return nil, status.Error(codes.Unauthenticated, "missing client certificate")
	}
	f.renews++
	return f.sign(req.CsrDer)
}

func (f *tlsPanel) OpenChannel(s pb.AgentChannel_OpenChannelServer) error {
	serial := peerSerial(s.Context())
	f.mu.Lock()
	if serial == "" || f.refuse[serial] {
		f.mu.Unlock()
		return status.Error(codes.Unauthenticated, "unknown certificate")
	}
	f.streams = append(f.streams, serial)
	f.mu.Unlock()
	// Accepted: say something (the agent promotes a renewed identity on
	// the first message).
	if err := s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Noop{Noop: &pb.Noop{}}}); err != nil {
		return err
	}
	<-s.Context().Done()
	return nil
}

func (f *tlsPanel) snapshot() (enrolls, renews int, streams []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enrolls, f.renews, append([]string(nil), f.streams...)
}

func startTLSPanel(t *testing.T, f *tlsPanel) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{f.ca.serverTLS(t)},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    f.ca.pool(),
		MinVersion:   tls.VersionTLS13,
	})
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAgentChannelServer(srv, f)
	pb.RegisterAgentEnrollmentServer(srv, f)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runAgent(t *testing.T, a *Agent) (cancel func(), errc chan error) {
	ctx, c := context.WithCancel(context.Background())
	errc = make(chan error, 1)
	go func() { errc <- a.Run(ctx) }()
	return func() { c(); <-errc }, errc
}

func tlsAgent(t *testing.T, addr, dir string, cfg *Config) *Agent {
	t.Helper()
	cfg.PanelAddr, cfg.ServerName = addr, "localhost"
	ids, err := loadIdentities(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAgent(cfg, "test", ids)
	a.backoffBase = 10 * time.Millisecond
	a.renewCheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { a.core.Teardown() })
	return a
}

// Key-less bootstrap: the agent generates its key, enrolls without a
// client certificate, then connects with the issued one. A restart does
// not enroll again; a new token in the bootstrap file re-enrolls; a
// refused token without any identity is a clear, permanent error.
func TestEnrollAgainstPanel(t *testing.T) {
	ca := newTestCA(t)
	f := &tlsPanel{t: t, ca: ca, token: "tok-1", life: 90 * 24 * time.Hour}
	addr := startTLSPanel(t, f)
	dir := t.TempDir()
	a := tlsAgent(t, addr, dir, &Config{EnrollmentToken: "tok-1", Identity: IdentityConfig{CAPEM: ca.pem}})
	stop, _ := runAgent(t, a)
	eventually(t, "a stream with the enrolled certificate", func() bool {
		_, _, s := f.snapshot()
		return len(s) > 0
	})
	stop()
	cur := a.ids.current()
	if _, _, s := f.snapshot(); s[0] != cur.leaf.SerialNumber.Text(16) {
		t.Fatal("stream not on the enrolled certificate")
	}
	if m := mode(t, filepath.Join(dir, identityFile)); m != 0o600 {
		t.Fatalf("identity mode %o", m)
	}
	// Restart with the same (used) token: no second enrollment.
	a2 := tlsAgent(t, addr, dir, &Config{EnrollmentToken: "tok-1", Identity: IdentityConfig{CAPEM: ca.pem}})
	stop, _ = runAgent(t, a2)
	eventually(t, "reconnect", func() bool { _, _, s := f.snapshot(); return len(s) >= 2 })
	stop()
	if e, _, _ := f.snapshot(); e != 1 {
		t.Fatalf("re-enrolled with a used token: %d", e)
	}
	// A new token: re-enroll (new key, new certificate).
	f.mu.Lock()
	f.token = "tok-2"
	f.mu.Unlock()
	a3 := tlsAgent(t, addr, dir, &Config{EnrollmentToken: "tok-2", Identity: IdentityConfig{CAPEM: ca.pem}})
	stop, _ = runAgent(t, a3)
	eventually(t, "re-enrollment", func() bool { e, _, _ := f.snapshot(); return e == 2 })
	stop()
	if a3.ids.current().leaf.SerialNumber.Cmp(cur.leaf.SerialNumber) == 0 {
		t.Fatal("re-enrollment kept the old certificate")
	}
	// Refused token, no identity: permanent error.
	a4 := tlsAgent(t, addr, t.TempDir(), &Config{EnrollmentToken: "wrong", Identity: IdentityConfig{CAPEM: ca.pem}})
	err := a4.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "enrollment refused") {
		t.Fatalf("want enrollment refused, got %v", err)
	}
	// The token never reaches the log/marker in clear.
	b, _ := os.ReadFile(filepath.Join(dir, enrolledMarker))
	if strings.Contains(string(b), "tok-2") {
		t.Fatal("token stored in clear")
	}
}

// Renewal with an injected clock: nothing before 2/3 of the lifetime;
// then Renew over the live mTLS stream, reconnect with the new identity,
// promote on the panel's first message. A renewed certificate the panel
// refuses is dropped (the current one keeps working); an answer that
// cannot be persisted leaves the current identity in use.
func TestRenewalFlow(t *testing.T) {
	ca := newTestCA(t)
	f := &tlsPanel{t: t, ca: ca, life: 90 * 24 * time.Hour, refuse: map[string]bool{}}
	addr := startTLSPanel(t, f)
	dir := t.TempDir()
	cfg := &Config{Identity: IdentityConfig{CAPEM: ca.pem}}
	a := tlsAgent(t, addr, dir, cfg)
	key, _ := newKey()
	issued := time.Now().Add(-time.Minute)
	if err := a.ids.storeEnrolled(key, ca.issue(t, &key.PublicKey, issued, 90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	first := a.ids.current()
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	a.now = func() time.Time { return time.Unix(0, clock.Load()) }

	stop, _ := runAgent(t, a)
	defer func() { stop() }()
	eventually(t, "first stream", func() bool { _, _, s := f.snapshot(); return len(s) == 1 })
	time.Sleep(200 * time.Millisecond)
	if _, r, _ := f.snapshot(); r != 0 {
		t.Fatal("renewed too early")
	}

	// 61 days later: renew.
	clock.Store(issued.Add(61 * 24 * time.Hour).UnixNano())
	eventually(t, "renewed stream", func() bool {
		_, _, s := f.snapshot()
		return len(s) >= 2 && s[len(s)-1] != first.leaf.SerialNumber.Text(16)
	})
	eventually(t, "promotion", func() bool { return a.ids.pending() == nil && a.ids.current() != first })
	second := a.ids.current()
	re, _ := loadIdentities(dir, cfg)
	if re.current().leaf.SerialNumber.Cmp(second.leaf.SerialNumber) != 0 || re.pending() != nil {
		t.Fatal("promotion not persisted")
	}

	// The panel refuses the next renewed certificate: dropped, the
	// current one keeps serving.
	f.mu.Lock()
	f.refuseIssued = true
	f.mu.Unlock()
	clock.Store(second.leaf.NotBefore.Add(61 * 24 * time.Hour).UnixNano())
	_, renewsBefore, _ := f.snapshot()
	eventually(t, "renewal attempt", func() bool { _, r, _ := f.snapshot(); return r > renewsBefore })
	eventually(t, "refused renewal dropped and current one back", func() bool {
		_, _, s := f.snapshot()
		return a.ids.pending() == nil && a.ids.current() == second &&
			s[len(s)-1] == second.leaf.SerialNumber.Text(16)
	})
	// ...and renewal backs off instead of hammering the panel.
	_, r1, _ := f.snapshot()
	time.Sleep(300 * time.Millisecond)
	if _, r2, _ := f.snapshot(); r2 > r1+1 {
		t.Fatalf("renewal retried without backoff: %d -> %d", r1, r2)
	}
	stop()
	stop = func() {}

	// Received but not persistable (here: a certificate for another key):
	// the current identity stays, nothing pending.
	f.mu.Lock()
	f.badRenew = true
	f.refuseIssued = false
	f.mu.Unlock()
	b := tlsAgent(t, addr, dir, cfg)
	b.now = a.now
	stop2, _ := runAgent(t, b)
	defer stop2()
	cur := b.ids.current()
	_, r0, _ := f.snapshot()
	eventually(t, "renewal attempt", func() bool { _, r, _ := f.snapshot(); return r > r0 })
	time.Sleep(100 * time.Millisecond)
	if b.ids.pending() != nil || b.ids.current() != cur {
		t.Fatal("an unusable renewal answer changed the identity")
	}
	b.renewMu.Lock()
	backedOff := !b.renewRetryAt.IsZero()
	b.renewMu.Unlock()
	if !backedOff {
		t.Fatal("failed renewal must back off")
	}
}

func TestHeartbeatCarriesConnectionsAndUptime(t *testing.T) {
	got := make(chan *pb.Heartbeat, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go heartbeatLoop(ctx, 10*time.Millisecond, func(m *pb.AgentUp) error {
		select {
		case got <- m.GetHeartbeat():
		default:
		}
		return nil
	}, func() (time.Duration, bool) { return 0, false }, func() agentStats {
		return agentStats{connections: 7, onlineUsers: 3, uptime: 42}
	}, newSampler(), func() *pb.CertStatus { return &pb.CertStatus{Domain: "n.example.com"} },
		func() *pb.SourceFilterStatus { return &pb.SourceFilterStatus{Error: "nft: x"} })
	hb := <-got
	if hb.Connections != 7 || hb.UptimeSeconds != 42 || hb.GetMetrics().GetOnlineUsers() != 3 ||
		hb.GetMetrics().GetXrayVersion() == "" || hb.GetCert().GetDomain() != "n.example.com" ||
		hb.GetSourceFilter().GetError() != "nft: x" {
		t.Fatalf("heartbeat %+v", hb)
	}
	a := NewAgent(&Config{}, "test", nil)
	a.startedAt = time.Now().Add(-90 * time.Second)
	if st := a.stats(); st.connections != 0 || st.onlineUsers != 0 || st.uptime < 90 {
		t.Fatalf("stats %+v", st)
	}
}
