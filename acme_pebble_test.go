package main

// In-process ACME test CA (pebble, the Let's Encrypt test server) with a
// tiny DNS server for its validation authority. No test ever talks to a
// real CA.

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

// testDNS answers A queries for the names it knows (127.0.0.1 unless set
// otherwise) and NXDOMAIN for the rest, over TCP (pebble's VA uses TCP).
type testDNS struct {
	mu    sync.Mutex
	names map[string]string // fqdn -> IPv4
	addr  string
}

func newTestDNS(t *testing.T) *testDNS {
	t.Helper()
	d := &testDNS{names: map[string]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.addr = ln.Addr().String()
	srv := &dns.Server{Listener: ln, Handler: d}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return d
}

func (d *testDNS) set(name, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.names[dns.Fqdn(strings.ToLower(name))] = ip
}

func (d *testDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, q := range r.Question {
		ip, ok := d.names[strings.ToLower(q.Name)]
		if !ok {
			m.Rcode = dns.RcodeNameError
			continue
		}
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   net.ParseIP(ip).To4(),
			})
		}
	}
	_ = w.WriteMsg(m)
}

// pebbleCA is a running pebble.
type pebbleCA struct {
	directory string
	// apiRoots: trust for the directory's own HTTPS (httptest cert).
	apiRoots *x509.CertPool
	// issuerRoots: the root pebble signs node certificates under.
	issuerRoots *x509.CertPool
	issuerPEM   []byte
	dns         *testDNS
}

// newPebbleCA starts pebble validating HTTP-01 on httpPort and TLS-ALPN-01 on
// tlsPort of whatever the DNS says. validity: certificate lifetime in
// seconds (0 = pebble's default).
func newPebbleCA(t *testing.T, httpPort, tlsPort int, validity uint64) *pebbleCA {
	t.Helper()
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	logger := log.New(io.Discard, "pebble ", 0)
	store := db.NewMemoryStore()
	profiles := map[string]ca.Profile{"default": {Description: "test", ValidityPeriod: validity}}
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, profiles)
	d := newTestDNS(t)
	vaImpl := va.New(logger, httpPort, tlsPort, false, d.addr, store)
	wfeImpl := wfe.New(logger, store, vaImpl, authority, nil, false, false, 0, 0)
	s := httptest.NewUnstartedServer(wfeImpl.Handler())
	s.StartTLS()
	t.Cleanup(s.Close)

	api := x509.NewCertPool()
	api.AddCert(s.Certificate())
	root := authority.GetRootCert(0)
	issuer := x509.NewCertPool()
	issuer.AddCert(root.Cert)
	return &pebbleCA{
		directory:   s.URL + wfe.DirectoryPath,
		apiRoots:    api,
		issuerRoots: issuer,
		issuerPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.DER}),
		dns:         d,
	}
}
