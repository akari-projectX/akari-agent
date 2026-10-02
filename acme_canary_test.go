//go:build canary

// Automatic node certificate end to end (protocol 6) with real xray
// clients: VLESS-WS-TLS, Trojan-TLS and Hysteria 2 get their certificate
// from an ACME CA (pebble, in process) and real clients that trust only
// that CA's root connect through them. The first CA certificate replaces
// the placeholder by swapping only the TLS inbounds (a connection on
// another inbound survives); a renewal is picked up by xray re-reading the
// files, without a rebuild, and every established connection survives.
//
// Not under -race: xray's certificate reload (transport/internet/tls
// setupOcspTicker) writes the certificate slot its GetCertificate reads
// without synchronization (upstream). `make test-canary`.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	_ "github.com/xtls/xray-core/proxy/hysteria"

	"akari/agent/pb"
)

// served returns the leaf a TLS (TCP) or QUIC (udp=true) handshake with
// the inbound presents, verified against roots for testDomain.
func served(t *testing.T, port int, udp bool, roots *x509.CertPool) (*x509.Certificate, error) {
	t.Helper()
	cfg := &tls.Config{ServerName: testDomain, RootCAs: roots, MinVersion: tls.VersionTLS12}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if udp {
		cfg.NextProtos = []string{"h3"}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := quic.DialAddr(ctx, addr, cfg, nil)
		if err != nil {
			return nil, err
		}
		defer c.CloseWithError(0, "")
		return c.ConnectionState().TLS.PeerCertificates[0], nil
	}
	cfg.NextProtos = []string{"http/1.1"}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0], nil
}

func TestACME_TLSInboundsGetAndHotReloadTheCertificate(t *testing.T) {
	cm, ca := newTestCertManager(t, 3600)
	cm.backoffBase = time.Second
	wsP, trP, hyP, vmP := freePort(t), freePort(t), freePort(t), freePort(t)
	const hyAuth = "0123456789abcdef0123456789abcdef"
	const trPass = "acme-trojan-password-0123"
	// As the panel's templates render them (node certificate credential
	// paths), plus ocspStapling: 1 so xray re-reads the files every second
	// instead of every hour (the production default; same code path).
	tlsIn := func(alpn string) string {
		return fmt.Sprintf(`"security":"tls","tlsSettings":{"serverName":%q,"alpn":[%q],"certificates":[{"certificateFile":%q,"keyFile":%q,"ocspStapling":1}]}`,
			testDomain, alpn, nodeCertCredFile, nodeKeyCredFile)
	}
	inb := fmt.Sprintf(`[
	 {"tag":"ws","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
	  "streamSettings":{"network":"ws","wsSettings":{"path":"/ws"},%s}},
	 {"tag":"tr","listen":"127.0.0.1","port":%d,"protocol":"trojan","settings":{"clients":[]},
	  "streamSettings":{"network":"tcp",%s}},
	 {"tag":"hy","listen":"127.0.0.1","port":%d,"protocol":"hysteria","settings":{"version":2,"clients":[]},
	  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2},%s}},
	 {"tag":"vm","listen":"127.0.0.1","port":%d,"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp"}}]`,
		wsP, tlsIn("http/1.1"), trP, tlsIn("http/1.1"), hyP, tlsIn("h3"), vmP)
	user := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{
		{InboundTag: "ws", Protocol: "vless", AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, idA)},
		{InboundTag: "tr", Protocol: "trojan", AccountJson: fmt.Sprintf(`{"password":%q}`, trPass)},
		{InboundTag: "hy", Protocol: "hysteria", AccountJson: fmt.Sprintf(`{"auth":%q}`, hyAuth)},
		{InboundTag: "vm", Protocol: "vmess", AccountJson: fmt.Sprintf(`{"id":%q}`, idA)},
	}}

	// The agent glue: Snapshot -> configureCert -> Rebuild; first CA
	// certificate -> onCertIssued.
	a := NewAgent(&Config{}, "test", nil)
	a.certs = cm
	cm.onIssued = func(string) { a.onCertIssued() }
	snap := &pb.ConfigSnapshot{ConfigVersion: 1, UserVersion: 1, InboundsJson: inb, Users: []*pb.UserOp{user},
		Acme: &pb.AcmeConfig{Domain: testDomain, DirectoryUrl: ca.directory}}
	a.applyMu.Lock()
	a.configureCert(snap)
	_, err := a.core.Rebuild(snap.InboundsJson, snap.Users)
	a.applyMu.Unlock()
	if err != nil {
		t.Fatalf("rebuild with the placeholder: %v", err)
	}
	defer a.core.Teardown()
	if !a.core.ServesPlaceholder() {
		t.Fatal("instance should serve the placeholder")
	}
	session := a.core.SessionID()
	if leaf, err := served(t, wsP, false, nil); err == nil || leaf != nil {
		t.Fatal("the placeholder must not verify")
	}

	echo := echoServer(t)
	clientTLS := func(alpn string) map[string]any {
		return map[string]any{"serverName": testDomain, "alpn": []string{alpn},
			"certificates": []any{map[string]any{"usage": "verify", "certificate": lines(string(ca.issuerPEM))}}}
	}
	client := func(out map[string]any) int {
		cp := freePort(t)
		clientInstance(t, map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
			"outbounds": []any{out},
		})
		return cp
	}
	vmC := client(map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
		"address": "127.0.0.1", "port": vmP, "users": []any{map[string]any{"id": idA, "security": "auto"}}}}}})
	open := func(name string, cp int) net.Conn {
		var lastErr error
		for i := 0; i < 30; i++ {
			c, err := dialRetry(cp)
			if err == nil {
				if err = echoOnce(c, name+"-hello"); err == nil {
					return c
				}
				c.Close()
			}
			lastErr = err
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: no relay: %v", name, lastErr)
		return nil
	}
	other := open("vmess", vmC)
	defer other.Close()

	// First order: the placeholder is replaced, only the TLS inbounds swap.
	cm.step(context.Background())
	if st := cm.Status(); st.State != pb.CertStatus_VALID {
		t.Fatalf("status %+v", st)
	}
	if a.core.ServesPlaceholder() || a.core.SessionID() != session {
		t.Fatal("swap must clear the placeholder flag without a rebuild")
	}
	if err := echoOnce(other, "vmess-after-swap"); err != nil {
		t.Fatalf("a connection on another inbound dropped at the swap: %v", err)
	}
	first, err := served(t, wsP, false, ca.issuerRoots)
	if err != nil {
		t.Fatalf("WS-TLS does not serve the CA certificate after the swap: %v", err)
	}
	if l, err := served(t, trP, false, ca.issuerRoots); err != nil || l.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("Trojan-TLS: %v", err)
	}
	var hyLeaf *x509.Certificate
	for i := 0; i < 30; i++ {
		if hyLeaf, err = served(t, hyP, true, ca.issuerRoots); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || hyLeaf.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("Hysteria2: %v", err)
	}

	// Real clients trusting only the CA root.
	wsC := client(map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
		"address": "127.0.0.1", "port": wsP, "users": []any{map[string]any{"id": idA, "encryption": "none"}}}}},
		"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": "/ws"}, "security": "tls", "tlsSettings": clientTLS("http/1.1")}})
	trC := client(map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{
		"address": "127.0.0.1", "port": trP, "password": trPass}}},
		"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": clientTLS("http/1.1")}})
	hyC := client(map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": hyP},
		"streamSettings": map[string]any{"network": "hysteria", "hysteriaSettings": map[string]any{"version": 2, "auth": hyAuth},
			"security": "tls", "tlsSettings": clientTLS("h3")}})
	conns := map[string]net.Conn{"vmess": other}
	for name, cp := range map[string]int{"vless-ws-tls": wsC, "trojan-tls": trC, "hysteria2": hyC} {
		conns[name] = open(name, cp)
		defer conns[name].Close()
	}

	// Renewal (a third of the lifetime left): new files, no rebuild, no
	// swap; xray serves the new certificate to new handshakes.
	cm.now = func() time.Time { return first.NotAfter.Add(-5 * time.Minute) }
	cm.step(context.Background())
	renewed := leafOf(t, cm.files(testDomain))
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed")
	}
	waitServed := func(name string, port int, udp bool) {
		var got *big.Int
		for i := 0; i < 60; i++ {
			if l, err := served(t, port, udp, ca.issuerRoots); err == nil {
				if got = l.SerialNumber; got.Cmp(renewed.SerialNumber) == 0 {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s still serves serial %v after the renewal (want %v)", name, got, renewed.SerialNumber)
	}
	waitServed("vless-ws-tls", wsP, false)
	waitServed("trojan-tls", trP, false)
	waitServed("hysteria2", hyP, true)
	if a.core.SessionID() != session {
		t.Fatal("renewal rebuilt the instance")
	}
	for name, c := range conns {
		for i := 0; i < 3; i++ {
			if err := echoOnce(c, fmt.Sprintf("%s-after-renewal-%d-%s", name, i, strings.Repeat("y", 1000))); err != nil {
				t.Fatalf("%s: established connection dropped by the renewal: %v", name, err)
			}
		}
	}
	// And new connections through every TLS inbound.
	for name, cp := range map[string]int{"vless-ws-tls": wsC, "trojan-tls": trC, "hysteria2": hyC} {
		c := open(name+"-new", cp)
		c.Close()
	}
}
