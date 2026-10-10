//go:build canary

// Billing canary (2026-10-10): an unlimited user's XTLS Vision download is
// counted while it flows, and a rebuild mid-download bills all of it. Before
// the fix xray's splice copy added the downlink bytes only when the
// connection ended, so the counter stayed at ~0 for the whole transfer and
// a teardown lost it.

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

// pacedTLSSource serves total bytes in 1 MiB chunks, one every gap, over
// TLS 1.3 (inner TLS is what makes Vision splice) after one request byte.
func pacedTLSSource(t *testing.T, c tls.Certificate, total int64, gap time.Duration) int {
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
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
				chunk := make([]byte, 1<<20)
				for sent := int64(0); sent < total; sent += int64(len(chunk)) {
					if _, err := cc.Write(chunk); err != nil {
						return
					}
					time.Sleep(gap)
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func downBytes(r *pb.TrafficReport) (down uint64) {
	if r == nil {
		return 0
	}
	for _, u := range r.Users {
		down += u.DownBytes
	}
	return down
}

func TestRT_VisionCountedWhileFlowing(t *testing.T) {
	certPEM, keyPEM, cert := selfSigned(t)
	m := NewCoreManager()
	defer m.Teardown()
	sp := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in-v","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
	  "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificate":%s,"key":%s}]}}}]`,
		sp, mustJSON(lines(certPEM)), mustJSON(lines(keyPEM)))
	const flow = "xtls-rprx-vision"
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{
		InboundTag: "in-v", Protocol: "vless", AccountJson: fmt.Sprintf(`{"flow":%q,"id":%q}`, flow, idA)}}}
	if _, err := m.Rebuild(inb, []*pb.UserOp{op}); err != nil {
		t.Fatal(err)
	}
	const total = 96 << 20
	src := pacedTLSSource(t, cert, total, 40*time.Millisecond) // ~25 MiB/s
	sum := sha256.Sum256(cert.Certificate[0])
	cp := freePort(t)
	clientInstance(t, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": src, "network": "tcp"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": sp, "users": []any{map[string]any{"id": idA, "flow": flow, "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
				"serverName": "rt.test", "pinnedPeerCertSha256": hex.EncodeToString(sum[:])}}}},
	})
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cp))
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer c.Close()
	if _, err := c.Write([]byte("D")); err != nil {
		t.Fatal(err)
	}
	got := make(chan int64, 1024)
	go func() {
		var n int64
		b := make([]byte, 256<<10)
		for {
			k, err := c.Read(b)
			n += int64(k)
			got <- n
			if err != nil {
				close(got)
				return
			}
		}
	}()
	var received int64
	var final *pb.TrafficReport
	deadline := time.After(60 * time.Second)
	for final == nil {
		select {
		case n, ok := <-got:
			if !ok {
				t.Fatalf("download ended (%d B) before the rebuild", received)
			}
			received = n
		case <-deadline:
			t.Fatal("timeout")
		}
		if received < total/2 {
			continue
		}
		// Mid-download the counter must already carry what the client has
		// (less what is still in flight in buffers).
		if c := downBytes(m.TrafficSnapshot()); c+8<<20 < uint64(received) {
			t.Fatalf("mid-download counter %d B, client already received %d B: the downlink is not counted as it flows", c, received)
		}
		f, err := m.Rebuild(inb, []*pb.UserOp{op})
		if err != nil {
			t.Fatal(err)
		}
		final = f
	}
	for n := range got {
		received = n
	}
	billed := downBytes(final) + downBytes(m.TrafficSnapshot())
	if billed < uint64(received) {
		t.Fatalf("rebuild mid-download: billed %d B of %d B received", billed, received)
	}
	t.Logf("received %d B, billed %d B (final %d B)", received, billed, downBytes(final))
}
