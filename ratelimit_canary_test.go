//go:build canary

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"akari/agent/pb"
)

// tlsSource accepts TLS 1.3 and sends n bytes on every connection.
func tlsSource(t *testing.T, c tls.Certificate, n int) int {
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
			go func() {
				defer cc.Close()
				var b [1]byte
				if _, err := io.ReadFull(cc, b[:]); err != nil {
					return
				}
				_, _ = cc.Write(make([]byte, n))
				_, _ = io.Copy(io.Discard, cc)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// The speed limit holds on the XTLS Vision path, whose splice would copy
// kernel-to-kernel past every reader/writer: a limited user's dispatch
// turns splice off (CanSpliceCopy = 3) and is paced; the same download
// unlimited is far faster.
func TestRT_VisionSpeedLimit(t *testing.T) {
	const rate = 1 << 20
	const n = 3 << 20
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
	src := tlsSource(t, cert, n)
	sum := sha256.Sum256(cert.Certificate[0])
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": src, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "flow": "xtls-rprx-vision", "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "rt.test", "pinnedPeerCertSha256": hex.EncodeToString(sum[:])}}}},
	})
	pull := func() time.Duration {
		raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
		if err != nil {
			t.Fatal(err)
		}
		c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		start := time.Now()
		if _, err := c.Write([]byte{'d'}); err != nil {
			t.Fatal(err)
		}
		if got, err := io.CopyN(io.Discard, c, n); err != nil || got != n {
			t.Fatalf("got %d of %d: %v", got, n, err)
		}
		return time.Since(start)
	}
	fast := pull()
	op.SpeedLimitBytesPerSec = rate
	if _, err := m.ApplyUserOps([]*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	slow := pull()
	want := time.Duration(n-rate/5) * time.Second / rate
	t.Logf("RT-VISION-LIMIT: unlimited %v, limited %v (want >= %v at %d B/s)", fast, slow, want, rate)
	if slow < want*95/100 || slow > want*14/10+300*time.Millisecond {
		t.Fatalf("Vision download not paced to the limit: %v, want ~%v", slow, want)
	}
}

// Mux: every sub-stream is a dispatch of the same user, so concurrent
// sub-streams share one budget (and the mux server's own links, which xray
// asserts to be *pipe.Reader, are never wrapped — only the outbound side).
func TestRT_MuxSpeedLimit(t *testing.T) {
	const rate = 256 << 10
	const n = 256 << 10 // per sub-stream, two of them
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, sp)
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, SpeedLimitBytesPerSec: rate,
		InboundUsers: []*pb.InboundUser{{InboundTag: "in-v", Protocol: "vless", AccountJson: fmt.Sprintf(`{"id":%q}`, idA)}}}
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
	var conns []net.Conn
	for i := 0; i < 2; i++ {
		c, err := dialRetry(cp)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := echoOnce(c, "pre"); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	start := time.Now()
	errs := make(chan error, 2)
	for _, c := range conns {
		go func(c net.Conn) { _, err := echoBulk(c, n); errs <- err }(c)
	}
	for range conns {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	took := time.Since(start)
	want := time.Duration(2*n-limitBurstMin) * time.Second / rate
	t.Logf("RT-MUX-LIMIT: 2 sub-streams x %d bytes in %v (want ~%v)", n, took, want)
	if took < want*95/100 || took > want*13/10+300*time.Millisecond {
		t.Fatalf("mux sub-streams not sharing the user's limit: %v, want ~%v", took, want)
	}
}

// UDP over the stream (VLESS UDP command): datagrams of a limited user are
// paced too (Hysteria2's UDP-carried streams: TestRT_ProtocolMatrix).
func TestRT_UDPSpeedLimit(t *testing.T) {
	const rate = 128 << 10
	const pkt = 1000
	const total = 256 << 10
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, sp)
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, SpeedLimitBytesPerSec: rate,
		InboundUsers: []*pb.InboundUser{{InboundTag: "in-v", Protocol: "vless", AccountJson: fmt.Sprintf(`{"id":%q}`, idA)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	ue, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ue.Close()
	go func() {
		b := make([]byte, 65536)
		for {
			k, a, err := ue.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = ue.WriteTo(b[:k], a)
		}
	}()
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": ue.LocalAddr().(*net.UDPAddr).Port, "network": "udp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "encryption": "none"}}}}}}},
	})
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 65536)
	// Lock-step windows of 8 datagrams: losses only cost a timeout.
	got := 0
	var start time.Time
	for sent := 0; sent < total; {
		for i := 0; i < 8; i++ {
			if _, err := c.Write(make([]byte, pkt)); err != nil {
				t.Fatal(err)
			}
			sent += pkt
		}
		for i := 0; i < 8; i++ {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			k, err := c.Read(b)
			if err != nil {
				break
			}
			got += k
		}
		if start.IsZero() {
			start = time.Now() // after the first window (handshake)
		}
	}
	took := time.Since(start)
	// The first window rode the free burst; the rest is paced.
	want := time.Duration(got-limitBurstMin) * time.Second / rate
	t.Logf("RT-UDP-LIMIT: %d of %d bytes echoed in %v (want ~%v at %d B/s each way)", got, total, took, want, rate)
	if got < total/2 {
		t.Fatalf("too few datagrams came back: %d", got)
	}
	if took < want*90/100 || took > want*14/10+500*time.Millisecond {
		t.Fatalf("UDP not paced to the limit: %v, want ~%v", took, want)
	}
}
