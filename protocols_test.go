package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"akari/agent/pb"
)

func b64key(n int, fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

func ssInbound(tag string, port int, method, psk string, withClients bool) string {
	clients := ""
	if withClients {
		clients = `,"clients":[]`
	}
	return fmt.Sprintf(`{"tag":%q,"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks",`+
		`"settings":{"method":%q,"password":%q,"network":"tcp,udp"%s}}`, tag, port, method, psk, clients)
}

func ssOp(user, tag, key string) *pb.UserOp {
	return &pb.UserOp{Op: pb.UserOp_ADD, UserId: user, InboundUsers: []*pb.InboundUser{{
		InboundTag: tag, Protocol: "shadowsocks", AccountJson: fmt.Sprintf(`{"password":%q}`, key)}}}
}

// A Shadowsocks 2022 inbound with a "clients" key (even empty) becomes
// xray's multi-user server; user keys are checked against the method.
func TestShadowsocks2022ManagedInbound(t *testing.T) {
	for _, tc := range []struct {
		method string
		n      int
	}{{"2022-blake3-aes-128-gcm", 16}, {"2022-blake3-aes-256-gcm", 32}} {
		m := NewCoreManager()
		inb := "[" + ssInbound("ss", freePort(t), tc.method, b64key(tc.n, 1), true) + "]"
		if _, err := m.Rebuild(inb, []*pb.UserOp{ssOp(userA, "ss", b64key(tc.n, 2))}); err != nil {
			t.Fatalf("%s: %v", tc.method, err)
		}
		if k := m.kinds["ss"]; k.protocol != "shadowsocks" || k.ssKeyLen != tc.n {
			t.Fatalf("%s: kind %+v", tc.method, k)
		}
		if m.UserCount() != 1 {
			t.Fatalf("%s: user not installed", tc.method)
		}
		other := 48 - tc.n // the other method's length
		for _, bad := range []string{
			fmt.Sprintf(`{"password":%q}`, b64key(other, 3)),
			`{"password":"not base64!"}`,
			fmt.Sprintf(`{"password":%q,"method":"x"}`, b64key(tc.n, 3)),
			`{"password":""}`,
		} {
			op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userB, InboundUsers: []*pb.InboundUser{{
				InboundTag: "ss", Protocol: "shadowsocks", AccountJson: bad}}}
			if _, err := m.ApplyUserOps([]*pb.UserOp{op}); err == nil {
				t.Fatalf("%s: accepted bad account %s", tc.method, bad)
			}
		}
		// A credential of another protocol never reaches the validator.
		if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userB, "ss", idB)}); err == nil ||
			!strings.Contains(err.Error(), "credential is vless, inbound is shadowsocks") {
			t.Fatalf("%s: protocol mismatch: %v", tc.method, err)
		}
		m.Teardown()
	}
}

func TestShadowsocksInboundsRefused(t *testing.T) {
	for name, in := range map[string]string{
		"chacha multi-user": ssInbound("ss", 0, "2022-blake3-chacha20-poly1305", b64key(32, 1), true),
		"short psk":         ssInbound("ss", 0, "2022-blake3-aes-256-gcm", b64key(16, 1), true),
		"bad psk":           ssInbound("ss", 0, "2022-blake3-aes-128-gcm", "%%%", true),
		"legacy multi-user": ssInbound("ss", 0, "aes-128-gcm", "pw", true),
	} {
		b, err := newInstance("[" + in + "]")
		if err == nil {
			_ = b.inst.Close()
			t.Fatalf("%s: accepted %s", name, in)
		}
	}
	// Without "clients" the inbound is xray's single-user server: it runs,
	// but takes no managed users.
	m := NewCoreManager()
	defer m.Teardown()
	inb := "[" + ssInbound("ss", freePort(t), "2022-blake3-aes-128-gcm", b64key(16, 1), false) + "]"
	if _, err := m.Rebuild(inb, []*pb.UserOp{ssOp(userA, "ss", b64key(16, 2))}); err == nil ||
		!strings.Contains(err.Error(), "takes no managed users") {
		t.Fatalf("single-user shadowsocks took a managed user: %v", err)
	}
}

// Shadowsocks 2022 users are added, removed, re-added and rotated by deltas
// like every other protocol's (protocol 8): xray's own RemoveUser, no
// tombstones, the state hash is exactly the live users, and a rotation
// swaps the key in place (same email, new credential) without a rebuild.
func TestSS2022NativeUserOps(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	port := freePort(t)
	inb := "[" + ssInbound("ss", port, "2022-blake3-aes-128-gcm", b64key(16, 1), true) + "]"
	a := ssOp(userA, "ss", b64key(16, 2))
	if _, err := m.Rebuild(inb, []*pb.UserOp{a, ssOp(userB, "ss", b64key(16, 3))}); err != nil {
		t.Fatal(err)
	}
	session := m.SessionID()
	apply := func(ops ...*pb.UserOp) {
		t.Helper()
		if _, err := m.ApplyUserOps(ops); err != nil {
			t.Fatal(err)
		}
	}
	removeA := &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: userA}
	apply(removeA)
	if m.UserCount() != 1 {
		t.Fatalf("users after removal = %d, want 1", m.UserCount())
	}
	if _, ok := m.applied[userA]; ok {
		t.Fatal("removed user still applied")
	}
	if got := m.StateHash(1); got == stateHash(1, inb, nil) {
		t.Fatal("state hash lost the remaining user")
	}
	// Removing an absentee is a no-op.
	apply(&pb.UserOp{Op: pb.UserOp_REMOVE, UserId: "nobody"})
	// Re-add the same key, then rotate it, then rotate with a remove in
	// between: each lands as a delta on the running instance.
	apply(a)
	first := m.applied[userA]["ss"].user
	apply(ssOp(userA, "ss", b64key(16, 6)))
	rotated := m.applied[userA]["ss"]
	if rotated.user == nil || rotated.user == first || rotated.account == a.InboundUsers[0].AccountJson {
		t.Fatalf("rotation did not install a new credential: %+v", rotated)
	}
	apply(removeA, ssOp(userA, "ss", b64key(16, 7)))
	if m.UserCount() != 2 {
		t.Fatalf("users = %d, want 2", m.UserCount())
	}
	if m.SessionID() != session {
		t.Fatal("a delta rebuilt the instance")
	}
	// The state hash is that of a fresh instance holding the same users.
	ref := NewCoreManager()
	defer ref.Teardown()
	if _, err := ref.Rebuild(swapPort(t, inb, port), []*pb.UserOp{ssOp(userA, "ss", b64key(16, 7)), ssOp(userB, "ss", b64key(16, 3))}); err != nil {
		t.Fatal(err)
	}
	if m.StateHash(1) != stateHash(1, inb, hashRecordsOf(ref)) {
		t.Fatal("state hash differs from a fresh instance with the same users")
	}
}

func TestBuildUserAccounts(t *testing.T) {
	hy := inboundKind{protocol: "hysteria"}
	if _, err := buildUser("hysteria", `{"auth":"0123456789abcdef0123"}`, userA, hy); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"auth":"short"}`, `{"auth":""}`, `{"auth":"0123456789abcdef0123","x":1}`} {
		if _, err := buildUser("hysteria", bad, userA, hy); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	vl := inboundKind{protocol: "vless"}
	if _, err := buildUser("vless", fmt.Sprintf(`{"id":%q,"flow":"xtls-rprx-vision"}`, idA), userA, vl); err != nil {
		t.Fatal(err)
	}
	if _, err := buildUser("vless", fmt.Sprintf(`{"id":%q,"flow":"xtls-rprx-direct"}`, idA), userA, vl); err == nil {
		t.Fatal("accepted a retired flow")
	}
	for _, extra := range []string{`"reverse":{"tag":"r"}`, `"encryption":"none"`, `"xorMode":1`, `"x":1`} {
		acct := fmt.Sprintf(`{"id":%q,"flow":"",%s}`, idA, extra)
		if _, err := buildUser("vless", acct, userA, vl); err == nil {
			t.Fatalf("accepted a vless account with extra field: %s", acct)
		}
	}
	if _, err := buildUser("vless", fmt.Sprintf(`{"id":%q}`, idA), userA, inboundKind{}); err == nil {
		t.Fatal("added a user to an unmanaged inbound")
	}
}

// R26: the gRPC transport is back. GO-2026-6443 (grpc-go panic on a
// request without :authority/Host) is in the xDS server routing path, which
// xray's plain grpc.Server does not use; the agent now pins the fixed
// grpc-go anyway. Requests with and without :authority, with and without
// END_STREAM, must leave the inbound serving.
func TestGRPCMissingAuthorityDoesNotPanic(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	p := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"g","listen":"127.0.0.1","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"svc"}}}]`, p)
	if _, err := m.Rebuild(inb, []*pb.UserOp{vlessUser(userA, "g", idA)}); err != nil {
		t.Fatal(err)
	}
	// Variants: with/without :authority, with/without END_STREAM on the
	// HEADERS frame (v1.84.0 crashes on the END_STREAM ones).
	for i := 0; i < 4; i++ {
		c, err := dialRetry(p)
		if err != nil {
			t.Fatalf("inbound gone after %d requests: %v", i, err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
			t.Fatal(err)
		}
		fr := http2.NewFramer(c, c)
		if err := fr.WriteSettings(); err != nil {
			t.Fatal(err)
		}
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		fields := []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":path", Value: "/svc/Tun"},
			{Name: "content-type", Value: "application/grpc"},
			{Name: "te", Value: "trailers"},
		}
		if i%2 == 1 {
			fields = append(fields, hpack.HeaderField{Name: ":authority", Value: "x"})
		}
		for _, f := range fields {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: i >= 2}); err != nil {
			t.Fatal(err)
		}
		// Read whatever comes back until the server answers the stream or
		// closes; a panic would have killed the process before this.
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			if f.Header().StreamID == 1 {
				break
			}
		}
		_ = c.Close()
	}
}

// dialRetry: some transports start listening asynchronously.
func dialRetry(port int) (net.Conn, error) {
	var err error
	for i := 0; i < 40; i++ {
		var c net.Conn
		if c, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			return c, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, err
}
