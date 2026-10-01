//go:build canary

// W8 protocol matrix: for every template the panel renders, a real xray
// client completes a handshake through the agent's CoreManager (the same
// code path the agent runs: gate dispatcher, dynamic users), relays data,
// and then loses it on revocation — the established connection is cut and
// a new one is refused. Run WITHOUT -race (Vision): `make test-canary`.

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
	// rebuild: revoke via Snapshot (Shadowsocks: users never leave a live
	// instance, see shrinkUnsafe), not via a delta.
	rebuild bool
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
	if tc.rebuild {
		if _, err := m.Rebuild(inb, nil); err != nil {
			t.Fatal(err)
		}
	} else if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	if echoOnce(c, "after") == nil {
		t.Fatalf("RT-%s: revoked connection still relays", tc.name)
	}
	if c2, err := dial(); err == nil {
		defer c2.Close()
		if echoOnce(c2, "new") == nil {
			t.Fatalf("RT-%s: revoked credential opened a new connection", tc.name)
		}
	}
	t.Logf("RT-%s: handshake ok, cut and refused after revoke", tc.name)
}

func TestRT_ProtocolMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	realityDest := tlsEcho(t, e.cert) // TLS 1.3 target REALITY borrows
	vless := func(flow string) string { return fmt.Sprintf(`{"flow":%q,"id":%q}`, flow, idA) }
	vlessOut := func(port int, flow string, stream map[string]any) map[string]any {
		return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": idA, "flow": flow, "encryption": "none"}}}}},
			"streamSettings": stream}
	}
	vlessIn := `"protocol":"vless","settings":{"clients":[],"decryption":"none"}`
	ssPSK := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ssUser := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	ssPSK256 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	ssUser256 := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	ssCase := func(name, method, psk, user string) matrixCase {
		return matrixCase{
			name: name, protocol: "shadowsocks", rebuild: true,
			inbound: func(int) string {
				return fmt.Sprintf(`"protocol":"shadowsocks","settings":{"method":%q,"password":%q,"clients":[],"network":"tcp,udp"}`, method, psk)
			},
			account: fmt.Sprintf(`{"password":%q}`, user),
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{
					"address": "127.0.0.1", "port": p, "method": method, "password": psk + ":" + user}}}}
			},
		}
	}
	hyAuth := "0123456789abcdef0123456789abcdef"
	cases := []matrixCase{
		{
			name: "VLESS-REALITY-Vision", protocol: "vless", innerTLS: true, account: vless("xtls-rprx-vision"),
			inbound: func(int) string {
				return `"protocol":"vless","settings":{"clients":[],"decryption":"none","flow":"xtls-rprx-vision"},"streamSettings":{"network":"tcp",` + e.serverReality(realityDest) + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "xtls-rprx-vision", map[string]any{"network": "tcp", "security": "reality", "realitySettings": e.clientReality()})
			},
		},
		{
			name: "VLESS-TLS-Vision", protocol: "vless", innerTLS: true, account: vless("xtls-rprx-vision"),
			inbound: func(int) string {
				return `"protocol":"vless","settings":{"clients":[],"decryption":"none","flow":"xtls-rprx-vision"},"streamSettings":{"network":"tcp",` + e.serverTLS() + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "xtls-rprx-vision", map[string]any{"network": "tcp", "security": "tls", "tlsSettings": e.clientTLS()})
			},
		},
		{
			name: "VLESS-REALITY-XHTTP", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"},` + e.serverReality(realityDest) + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/xh", "mode": "auto"},
					"security": "reality", "realitySettings": e.clientReality()})
			},
		},
		{
			name: "VLESS-XHTTP", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"}}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/xh", "mode": "packet-up"}})
			},
		},
		{
			name: "VLESS-XHTTP-TLS", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/xh","mode":"auto"},` + e.serverTLS() + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/xh", "mode": "stream-one"},
					"security": "tls", "tlsSettings": e.clientTLS("h2")})
			},
		},
		{
			name: "VLESS-HTTPUpgrade", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"path":"/hu"}}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "httpupgrade", "httpupgradeSettings": map[string]any{"path": "/hu"}})
			},
		},
		{
			name: "VLESS-HTTPUpgrade-TLS", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"httpupgrade","httpupgradeSettings":{"path":"/hu"},` + e.serverTLS("http/1.1") + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "httpupgrade", "httpupgradeSettings": map[string]any{"path": "/hu"},
					"security": "tls", "tlsSettings": e.clientTLS("http/1.1")})
			},
		},
		{
			name: "VLESS-WS-TLS", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"ws","wsSettings":{"path":"/ws"},` + e.serverTLS("http/1.1") + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/ws"},
					"security": "tls", "tlsSettings": e.clientTLS("http/1.1")})
			},
		},
		{
			name: "VLESS-gRPC-TLS", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"svc"},` + e.serverTLS("h2") + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "svc"},
					"security": "tls", "tlsSettings": e.clientTLS("h2")})
			},
		},
		{
			name: "VLESS-REALITY-gRPC", protocol: "vless", account: vless(""),
			inbound: func(int) string {
				return vlessIn + `,"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"svc"},` + e.serverReality(realityDest) + `}`
			},
			outbound: func(p int) map[string]any {
				return vlessOut(p, "", map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "svc", "multiMode": true},
					"security": "reality", "realitySettings": e.clientReality()})
			},
		},
		{
			name: "VMess-TCP", protocol: "vmess", account: fmt.Sprintf(`{"id":%q}`, idA),
			inbound: func(int) string {
				return `"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp"}`
			},
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": p, "users": []any{map[string]any{"id": idA, "security": "auto"}}}}}}
			},
		},
		{
			name: "VMess-WS", protocol: "vmess", account: fmt.Sprintf(`{"id":%q}`, idA),
			inbound: func(int) string {
				return `"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vm"}}`
			},
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": p, "users": []any{map[string]any{"id": idA, "security": "auto"}}}}},
					"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/vm"}}}
			},
		},
		{
			name: "Trojan-WS-TLS", protocol: "trojan", account: `{"password":"rt-trojan-password-0123"}`,
			inbound: func(int) string {
				return `"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/tj"},` + e.serverTLS("http/1.1") + `}`
			},
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{
					"address": "127.0.0.1", "port": p, "password": "rt-trojan-password-0123"}}},
					"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/tj"},
						"security": "tls", "tlsSettings": e.clientTLS("http/1.1")}}
			},
		},
		{
			name: "Trojan-gRPC-TLS", protocol: "trojan", account: `{"password":"rt-trojan-password-0123"}`,
			inbound: func(int) string {
				return `"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"tg"},` + e.serverTLS("h2") + `}`
			},
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{
					"address": "127.0.0.1", "port": p, "password": "rt-trojan-password-0123"}}},
					"streamSettings": map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "tg"},
						"security": "tls", "tlsSettings": e.clientTLS("h2")}}
			},
		},
		ssCase("SS2022-AES128", "2022-blake3-aes-128-gcm", ssPSK, ssUser),
		ssCase("SS2022-AES256", "2022-blake3-aes-256-gcm", ssPSK256, ssUser256),
		{
			name: "Hysteria2", protocol: "hysteria", account: fmt.Sprintf(`{"auth":%q}`, hyAuth),
			inbound: func(int) string {
				return `"protocol":"hysteria","settings":{"version":2,"clients":[]},"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2},` + e.serverTLS("h3") + `}`
			},
			outbound: func(p int) map[string]any {
				return map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": p},
					"streamSettings": map[string]any{"network": "hysteria", "hysteriaSettings": map[string]any{"version": 2, "auth": hyAuth},
						"security": "tls", "tlsSettings": e.clientTLS("h3")}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runMatrixCase(t, e, tc) })
	}
}
