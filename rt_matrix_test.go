//go:build canary

// W8 protocol matrix: for every template the panel renders, a real xray
// client completes a handshake through the agent's CoreManager (the same
// code path the agent runs: gate dispatcher, dynamic users), relays data,
// and then loses it on revocation — the established connection is cut and
// a new one is refused. W7: re-added with a speed limit, a new connection is
// paced to it (every protocol, including SS2022 and Hysteria2 over QUIC). W9: removed
// and re-added (same credential, with and without a limit), the same client
// connects again, and is cut again by the next removal. Run WITHOUT -race
// (Vision): `make test-canary`.

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/vless"

	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"

	"akari/agent/pb"
)

type matrixEnv struct {
	certPEM, keyPEM string
	cert            tls.Certificate
	pin             string
	realityPriv     string
	realityPub      string
}

func newMatrixEnv(t *testing.T) *matrixEnv {
	certPEM, keyPEM, cert := selfSigned(t)
	sum := sha256.Sum256(cert.Certificate[0])
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &matrixEnv{
		certPEM: certPEM, keyPEM: keyPEM, cert: cert, pin: hex.EncodeToString(sum[:]),
		realityPriv: base64.RawURLEncoding.EncodeToString(k.Bytes()),
		realityPub:  base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()),
	}
}

// serverTLS: the node certificate inline (the panel's templates point at
// the systemd credential files instead; same xray fields).
func (e *matrixEnv) serverTLS(alpn ...string) string {
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	return fmt.Sprintf(`"security":"tls","tlsSettings":{"serverName":"rt.test","alpn":%s,"certificates":[{"certificate":%s,"key":%s}]}`,
		mustJSON(alpn), mustJSON(lines(e.certPEM)), mustJSON(lines(e.keyPEM)))
}

func (e *matrixEnv) clientTLS(alpn ...string) map[string]any {
	m := map[string]any{"serverName": "rt.test", "pinnedPeerCertSha256": e.pin}
	if len(alpn) > 0 {
		m["alpn"] = alpn
	}
	return m
}

func (e *matrixEnv) serverReality(destPort int) string {
	return fmt.Sprintf(`"security":"reality","realitySettings":{"dest":"127.0.0.1:%d","serverNames":["rt.test"],"privateKey":%q,"shortIds":["0123456789abcdef"],"publicKey":%q,"shortId":"0123456789abcdef","fingerprint":"chrome"}`,
		destPort, e.realityPriv, e.realityPub)
}

func (e *matrixEnv) clientReality() map[string]any {
	return map[string]any{"serverName": "rt.test", "fingerprint": "chrome", "publicKey": e.realityPub, "shortId": "0123456789abcdef"}
}

type matrixCase struct {
	name     string
	protocol string
	inbound  func(port int) string // "<protocol+settings>,<streamSettings>" body
	account  string
	outbound func(port int) map[string]any
	// innerTLS: the proxied payload is TLS 1.3 (exercises Vision splice).
	innerTLS bool
}

func runMatrixCase(t *testing.T, e *matrixEnv, tc matrixCase) {
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in","listen":"127.0.0.1","port":%d,%s}]`, sp, tc.inbound(sp))
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in", Protocol: tc.protocol, AccountJson: tc.account}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	var echo int
	if tc.innerTLS {
		echo = tlsEcho(t, e.cert)
	} else {
		echo = echoServer(t)
	}
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{tc.outbound(sp)},
	})
	dial := func() (net.Conn, error) {
		raw, err := dialRetry(cp)
		if err != nil || !tc.innerTLS {
			return raw, err
		}
		return tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}), nil
	}
	var c net.Conn
	var err error
	// Listeners of some transports (QUIC, gRPC) come up asynchronously.
	for i := 0; i < 20; i++ {
		if c, err = dial(); err == nil {
			if err = echoOnce(c, "pre-"+strings.Repeat("x", 3000)); err == nil {
				break
			}
			c.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("handshake/relay before revoke: %v", err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		if err := echoOnce(c, fmt.Sprintf("pre%d", i)); err != nil {
			t.Fatalf("relay before revoke: %v", err)
		}
	}
	// Billing: the relayed bytes are counted for the user (an anonymous
	// connection would relay but count nothing — the Hysteria bug).
	var up, down uint64
	if rep := m.TrafficSnapshot(); rep != nil {
		for _, u := range rep.Users {
			if u.UserId == userA {
				up, down = u.UpBytes, u.DownBytes
			}
		}
	}
	if up < 3000 || down < 3000 {
		t.Fatalf("RT-%s: user counters up=%d down=%d after relaying >3000 bytes", tc.name, up, down)
	}
	// W7: a limit-only change (a delta with the same credentials, what the
	// panel sends when a plan's speed changes) closes the user's unthrottled
	// connections; a new one through a fresh client is paced to the limit
	// (both directions of the echo).
	const rate = 256 << 10
	const n = 512 << 10
	op.SpeedLimitBytesPerSec = rate
	if _, err := m.ApplyUserOps([]*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	if echoOnce(c, "unthrottled") == nil {
		t.Fatalf("RT-%s: unthrottled connection still relays after the new limit", tc.name)
	}
	// A fresh client (some keep sessions the agent just closed).
	cp2 := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp2, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{tc.outbound(sp)},
	})
	cp = cp2
	c.Close()
	var lc net.Conn
	for i := 0; i < 30; i++ {
		if lc, err = dial(); err == nil {
			if err = echoOnce(lc, "limited"); err == nil {
				break
			}
			lc.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("RT-%s: reconnect with a limit: %v", tc.name, err)
	}
	took, err := echoBulk(lc, n)
	if err != nil {
		t.Fatalf("RT-%s: limited transfer: %v", tc.name, err)
	}
	// Up and down are paced concurrently: ~n/rate, not twice that.
	want := time.Duration(n-limitBurstMin) * time.Second / rate
	t.Logf("RT-%s-LIMIT: %d bytes echoed in %v at %d B/s (want ~%v)", tc.name, n, took, rate, want)
	if took < want*95/100 || took > want*13/10+300*time.Millisecond {
		t.Fatalf("RT-%s: transfer not paced to the limit: %v, want ~%v", tc.name, took, want)
	}
	c = lc // the revocation below runs on the throttled connection
	defer lc.Close()
	remove := func(c net.Conn, phase string) {
		t.Helper()
		if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
			t.Fatal(err)
		}
		if echoOnce(c, "after") == nil {
			t.Fatalf("RT-%s: revoked connection still relays (%s)", tc.name, phase)
		}
		if c2, err := dial(); err == nil {
			defer c2.Close()
			if echoOnce(c2, "new") == nil {
				t.Fatalf("RT-%s: revoked credential opened a new connection (%s)", tc.name, phase)
			}
		}
	}
	// Revocation is a delta for every protocol, Shadowsocks 2022 included
	// (W9: the credential stays in xray's table as a gate-refused
	// tombstone, see shrinkUnsafe).
	remove(c, "first removal")
	t.Logf("RT-%s: handshake ok, cut and refused after revoke", tc.name)

	// W9: remove -> re-add (a plan expires, then is renewed) must connect
	// again through the SAME client, which may keep sessions across the
	// removal: Hysteria 2 authenticates once per QUIC connection, so its
	// streams carry the *MemoryUser of that handshake; a re-add that
	// installed a fresh pointer locked such a client out until the node
	// was rebuilt. Re-added with the limit, then without.
	for _, limit := range []uint64{rate, 0} {
		readd := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: op.InboundUsers, SpeedLimitBytesPerSec: limit}
		if _, err := m.ApplyUserOps([]*pb.UserOp{readd}); err != nil {
			t.Fatalf("RT-%s: re-add: %v", tc.name, err)
		}
		var rc net.Conn
		for i := 0; i < 30; i++ {
			if rc, err = dial(); err == nil {
				if err = echoOnce(rc, "readd"); err == nil {
					break
				}
				rc.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("RT-%s: re-added user (limit %d) cannot connect through the same client: %v", tc.name, limit, err)
		}
		took, err := echoBulk(rc, n)
		if err != nil {
			rc.Close()
			t.Fatalf("RT-%s: re-added transfer (limit %d): %v", tc.name, limit, err)
		}
		if limit > 0 && (took < want*95/100 || took > want*13/10+300*time.Millisecond) {
			rc.Close()
			t.Fatalf("RT-%s: re-added transfer not paced to the limit: %v, want ~%v", tc.name, took, want)
		}
		if limit == 0 && took > want/2 {
			rc.Close()
			t.Fatalf("RT-%s: re-added without a limit, still paced: %v", tc.name, took)
		}
		t.Logf("RT-%s-READD: limit %d, %d bytes echoed in %v", tc.name, limit, n, took)
		remove(rc, fmt.Sprintf("removal after re-add with limit %d", limit))
		rc.Close()
	}
}

// echoBulk sends n bytes (concurrently) and reads them back; the time
// until the last byte returned.
func echoBulk(c net.Conn, n int) (time.Duration, error) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.SetDeadline(time.Time{})
	start := time.Now()
	werr := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, n)); werr <- err }()
	b := make([]byte, 64<<10)
	got := 0
	for got < n {
		k, err := c.Read(b)
		got += k
		if err != nil {
			return 0, fmt.Errorf("read %d of %d: %w", got, n, err)
		}
	}
	if err := <-werr; err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// TestRT_ProtocolMatrix runs every end-to-end scenario of the protocol
// manifest (proto/protocols.toml [[scenario]], W26): the case table is
// composed from per-protocol, per-transport and per-security builders
// (scenarioCase); a scenario without a builder fails the test, so adding a
// combination to the manifest means teaching the canary to run it.
func TestRT_ProtocolMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	realityDest := tlsEcho(t, e.cert) // TLS 1.3 target REALITY borrows
	if len(manifest.Scenario) == 0 {
		t.Fatal("the manifest lists no scenarios")
	}
	for _, sc := range manifest.Scenario {
		tc, err := scenarioCase(e, realityDest, sc)
		if err != nil {
			t.Fatalf("%v: %v", sc, err)
		}
		t.Run(tc.name, func(t *testing.T) { runMatrixCase(t, e, tc) })
	}
}

// matrixPart: one layer's contribution to the server inbound (JSON members)
// and to the client outbound's streamSettings.
type matrixPart struct {
	server []string
	client map[string]any
}

// scenarioCase composes a manifest scenario into a canary case.
func scenarioCase(e *matrixEnv, realityDest int, sc manifestScenario) (matrixCase, error) {
	p := manifest.protocolByID(sc.Protocol)
	if p == nil {
		return matrixCase{}, fmt.Errorf("unknown protocol")
	}
	tc := matrixCase{name: sc.Name, protocol: p.Wire}
	// Security first: the transport's client settings depend on it.
	var alpn []string
	if tr := manifestTransport(sc.Transport); tr != nil {
		alpn = tr.ALPN
	}
	if sc.Transport == "native" {
		alpn = p.ALPN
	}
	var sec matrixPart
	switch sc.Security {
	case "none":
	case "tls":
		sec.server = []string{e.serverTLS(alpn...)}
		sec.client = map[string]any{"security": "tls"}
		if sc.Transport == "tcp" {
			sec.client["tlsSettings"] = e.clientTLS()
		} else {
			sec.client["tlsSettings"] = e.clientTLS(alpn[0])
		}
	case "reality":
		sec.server = []string{e.serverReality(realityDest)}
		sec.client = map[string]any{"security": "reality", "realitySettings": e.clientReality()}
	default:
		return tc, fmt.Errorf("no canary builder for security %q", sc.Security)
	}
	var net matrixPart
	switch sc.Transport {
	case "tcp":
		net = matrixPart{[]string{`"network":"tcp"`}, map[string]any{"network": "tcp"}}
	case "ws":
		net = matrixPart{[]string{`"network":"ws","wsSettings":{"path":"/ws"}`},
			map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/ws"}}}
	case "httpupgrade":
		net = matrixPart{[]string{`"network":"httpupgrade","httpupgradeSettings":{"path":"/hu"}`},
			map[string]any{"network": "httpupgrade", "httpupgradeSettings": map[string]any{"path": "/hu"}}}
	case "xhttp":
		// The client exercises a different XHTTP mode per security (the
		// server accepts all of them in "auto").
		mode := map[string]string{"none": "packet-up", "tls": "stream-one", "reality": "auto"}[sc.Security]
		net = matrixPart{[]string{`"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"}`},
			map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/xh", "mode": mode}}}
	case "grpc":
		grpc := map[string]any{"serviceName": "svc"}
		if sc.Security == "reality" {
			grpc["multiMode"] = true
		}
		net = matrixPart{[]string{`"network":"grpc","grpcSettings":{"serviceName":"svc"}`},
			map[string]any{"network": "grpc", "grpcSettings": grpc}}
	case "native":
		if sc.Protocol == "hysteria2" {
			net = matrixPart{[]string{`"network":"hysteria","hysteriaSettings":{"version":2}`},
				map[string]any{"network": "hysteria"}}
		}
	default:
		return tc, fmt.Errorf("no canary builder for transport %q", sc.Transport)
	}
	server := append(net.server, sec.server...)
	client := map[string]any{}
	for _, part := range []map[string]any{net.client, sec.client} {
		for k, v := range part {
			client[k] = v
		}
	}
	stream := ""
	if len(server) > 0 {
		stream = `,"streamSettings":{` + strings.Join(server, ",") + `}`
	}
	switch sc.Protocol {
	case "vless":
		flow := sc.Options["flow"]
		tc.innerTLS = flow == vless.XRV // Vision splice runs on inner TLS
		settings := `{"clients":[],"decryption":"none"}`
		if flow != "" {
			settings = fmt.Sprintf(`{"clients":[],"decryption":"none","flow":%q}`, flow)
		}
		tc.account = fmt.Sprintf(`{"flow":%q,"id":%q}`, flow, idA)
		tc.inbound = func(int) string { return `"protocol":"vless","settings":` + settings + stream }
		tc.outbound = func(port int) map[string]any {
			return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": idA, "flow": flow, "encryption": "none"}}}}},
				"streamSettings": client}
		}
	case "vmess":
		tc.account = fmt.Sprintf(`{"id":%q}`, idA)
		tc.inbound = func(int) string { return `"protocol":"vmess","settings":{"clients":[]}` + stream }
		tc.outbound = func(port int) map[string]any {
			return map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": idA, "security": "auto"}}}}},
				"streamSettings": client}
		}
	case "trojan":
		const pw = "rt-trojan-password-0123"
		tc.account = fmt.Sprintf(`{"password":%q}`, pw)
		tc.inbound = func(int) string { return `"protocol":"trojan","settings":{"clients":[]}` + stream }
		tc.outbound = func(port int) map[string]any {
			return map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "password": pw}}},
				"streamSettings": client}
		}
	case "ss2022":
		method := sc.Options["method"]
		n := p.option("method").keyLens()[method]
		if n == 0 {
			return tc, fmt.Errorf("no key length for method %q", method)
		}
		psk := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("0123456789abcdef", 2)[:n]))
		user := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("fedcba9876543210", 2)[:n]))
		tc.account = fmt.Sprintf(`{"password":%q}`, user)
		tc.inbound = func(int) string {
			return fmt.Sprintf(`"protocol":"shadowsocks","settings":{"method":%q,"password":%q,"clients":[],"network":"tcp,udp"}`, method, psk) + stream
		}
		tc.outbound = func(port int) map[string]any {
			return map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{
				"address": "127.0.0.1", "port": port, "method": method, "password": psk + ":" + user}}}}
		}
	case "hysteria2":
		const auth = "0123456789abcdef0123456789abcdef"
		tc.account = fmt.Sprintf(`{"auth":%q}`, auth)
		tc.inbound = func(int) string { return `"protocol":"hysteria","settings":{"version":2,"clients":[]}` + stream }
		client["hysteriaSettings"] = map[string]any{"version": 2, "auth": auth}
		tc.outbound = func(port int) map[string]any {
			return map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": port},
				"streamSettings": client}
		}
	default:
		return tc, fmt.Errorf("no canary builder for protocol %q", sc.Protocol)
	}
	return tc, nil
}

func manifestTransport(id string) *manifestLayer {
	for i := range manifest.Transport {
		if manifest.Transport[i].ID == id {
			return &manifest.Transport[i]
		}
	}
	return nil
}
