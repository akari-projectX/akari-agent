//go:build canary

// Red-team revocation canaries (R10): per-protocol proof that removing a
// user cuts its live connections. Run WITHOUT -race (xray's Vision client
// trips checkptr): `make test-canary` (part of `make test`).

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"

	"akari/agent/pb"
)

func tlsEcho(t *testing.T, c tls.Certificate) int {
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			cc, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer cc.Close(); io.Copy(cc, cc) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func lines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

func clientInstance(t *testing.T, cfg map[string]any) *core.Instance {
	b, _ := json.Marshal(cfg)
	jc, err := confserial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := jc.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(pc)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return inst
}

func echoOnce(c net.Conn, msg string) error {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	b := make([]byte, len(msg))
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != msg {
		return fmt.Errorf("mismatch")
	}
	return nil
}

func closedWithin(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	var b [1]byte
	_, err := c.Read(b[:])
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

// Revocation of a live VLESS+Vision connection whose inner traffic is TLS1.3 (splice path).
func TestRT_VisionSpliceRevocation(t *testing.T) {
	certPEM, keyPEM, cert := selfSigned(t)
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
	  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]}}}]`,
		sp, mustJSON(lines(certPEM)), mustJSON(lines(keyPEM)))
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in-v", Protocol: "vless",
		AccountJson: fmt.Sprintf(`{"flow":"xtls-rprx-vision","id":%q}`, idA)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	echo := tlsEcho(t, cert)
	sum := sha256.Sum256(cert.Certificate[0])
	pin := hex.EncodeToString(sum[:])
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "flow": "xtls-rprx-vision", "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "rt.test", "pinnedPeerCertSha256": pin}}}},
	})
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer c.Close()
	for i := 0; i < 5; i++ {
		if err := echoOnce(c, fmt.Sprintf("pre%d-%s", i, strings.Repeat("x", 2000))); err != nil {
			t.Fatalf("pre echo: %v", err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	gone := closedWithin(c, 3*time.Second)
	still := echoOnce(c, "after") == nil
	t.Logf("RT-VISION: closed_within_3s=%v echo_after_revoke_ok=%v", gone, still)
	if still {
		t.Fatal("RT: revoked Vision/splice connection still relays data")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// Trojan (plain TCP, no TLS) live connection revoke.
func TestRT_TrojanRevocation(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-t","listen":"127.0.0.1","port":%d,"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"tcp"}}]`, sp)
	pw := "rt-password-1"
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in-t", Protocol: "trojan", AccountJson: fmt.Sprintf(`{"password":%q}`, pw)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	cp := freePort(t)
	echo := echoServer(t)
	clientInstance(t, map[string]any{
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": sp, "password": pw}}}}},
	})
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := echoOnce(c, "pre"); err != nil {
		t.Fatalf("pre: %v", err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	still := echoOnce(c, "after") == nil
	t.Logf("RT-TROJAN: echo_after_revoke_ok=%v", still)
	if still {
		t.Fatal("RT: revoked trojan connection still relays")
	}
}

// VMess live connection revoke (no vmess canary existed: the protocol had
// no test of any kind).
func TestRT_VmessRevocation(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-m","listen":"127.0.0.1","port":%d,"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp"}}]`, sp)
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in-m", Protocol: "vmess", AccountJson: fmt.Sprintf(`{"id":%q}`, idA)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	cp := freePort(t)
	echo := echoServer(t)
	clientInstance(t, map[string]any{
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "security": "auto"}}}}}}},
	})
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := echoOnce(c, "pre"); err != nil {
		t.Fatalf("pre: %v", err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	still := echoOnce(c, "after") == nil
	t.Logf("RT-VMESS: echo_after_revoke_ok=%v", still)
	if still {
		t.Fatal("RT: revoked vmess connection still relays")
	}
	// A new connection with the revoked credential gets nothing either.
	c2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err == nil {
		defer c2.Close()
		if echoOnce(c2, "new") == nil {
			t.Fatal("RT: revoked vmess credential opened a new connection")
		}
	}
}

// Mux: sub-streams of one multiplexed VLESS connection all belong to the
// user. Revocation must cut the established sub-stream and refuse NEW
// sub-streams on the same (still open) mux connection.
func TestRT_MuxSubStreamRevocation(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, sp)
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{InboundTag: "in-v", Protocol: "vless", AccountJson: fmt.Sprintf(`{"id":%q}`, idA)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	echo := echoServer(t)
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": echo, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "encryption": "none"}}}}},
			"mux": map[string]any{"enabled": true, "concurrency": 8}}},
	})
	dial := func() (net.Conn, error) { return net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp)) }
	c1, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if err := echoOnce(c1, "pre"); err != nil {
		t.Fatalf("pre: %v", err)
	}
	// A second sub-stream over the same mux connection works before revoke.
	c2, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := echoOnce(c2, "pre2"); err != nil {
		t.Fatalf("second mux sub-stream: %v", err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	for i, c := range []net.Conn{c1, c2} {
		if echoOnce(c, "after") == nil {
			t.Fatalf("RT: established mux sub-stream %d still relays after revoke", i+1)
		}
	}
	c3, err := dial()
	if err == nil {
		defer c3.Close()
		if echoOnce(c3, "new") == nil {
			t.Fatal("RT: a NEW mux sub-stream was admitted after revoke")
		}
	}
	t.Log("RT-MUX: established and new sub-streams refused after revoke")
}
