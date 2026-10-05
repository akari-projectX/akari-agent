package main

// M2-6: agent overhead at the M2 target scale (10k users per node, two
// inbounds each, like the panel's bench data set). Results are recorded in
// akari-panel/docs/PERF.md.
//
//	go test -run '^$' -bench . -benchmem -benchtime 5x ./...      (quick)
//	go test -run '^$' -bench . -benchmem ./...

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"

	"akari/agent/pb"
)

const benchUsersN = 10_000

func benchPort(tb testing.TB) int {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func benchUserID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// benchOp: user i on both inbounds, credential generation g.
func benchOp(i, g int) *pb.UserOp {
	acct := func(tag string) string {
		return fmt.Sprintf(`{"flow":"","id":"%08d-%04d-4000-8000-%012d"}`, g, len(tag), i)
	}
	return &pb.UserOp{Op: pb.UserOp_ADD, UserId: benchUserID(i), InboundUsers: []*pb.InboundUser{
		{InboundTag: "in-a", Protocol: "vless", AccountJson: acct("in-a")},
		{InboundTag: "in-b", Protocol: "vless", AccountJson: acct("in-bb")},
	}}
}

func benchUsers(n int) []*pb.UserOp {
	ops := make([]*pb.UserOp, n)
	for i := range ops {
		ops[i] = benchOp(i, 0)
	}
	return ops
}

// benchCore: a running instance with n users, all with traffic counters.
func benchCore(tb testing.TB, n int) *CoreManager {
	tb.Helper()
	m := NewCoreManager()
	if _, err := m.Rebuild(twoInbounds(benchPort(tb), benchPort(tb)), benchUsers(n)); err != nil {
		tb.Fatal(err)
	}
	m.mu.Lock()
	for i := 0; i < n; i++ {
		stampUser(m.instance, benchUserID(i), int64(1000+i))
	}
	m.mu.Unlock()
	tb.Cleanup(func() { m.Teardown() })
	return m
}

// A Snapshot = full xray rebuild with 10k users (20k credentials).
func BenchmarkRebuild10k(b *testing.B) {
	m := NewCoreManager()
	defer m.Teardown()
	inb := twoInbounds(benchPort(b), benchPort(b))
	users := benchUsers(benchUsersN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Rebuild(inb, users); err != nil {
			b.Fatal(err)
		}
	}
}

// W28-a: the same 20k credentials as per-entrance users: 10k users each on
// the direct inbound ("<id>") and on one relay's derived inbound
// ("<id>#1"), one UserOp each (what the panel sends from protocol 7 on).
func benchEntranceOps(n int) []*pb.UserOp {
	ops := make([]*pb.UserOp, 0, 2*n)
	for i := 0; i < n; i++ {
		acct := func(tag string) string {
			return fmt.Sprintf(`{"flow":"","id":"%08d-%04d-4000-8000-%012d"}`, 0, len(tag), i)
		}
		ops = append(ops,
			&pb.UserOp{Op: pb.UserOp_ADD, UserId: benchUserID(i), InboundUsers: []*pb.InboundUser{
				{InboundTag: "in-a", Protocol: "vless", AccountJson: acct("in-a")}}},
			&pb.UserOp{Op: pb.UserOp_ADD, UserId: benchUserID(i) + "#1", InboundUsers: []*pb.InboundUser{
				{InboundTag: "in-b", Protocol: "vless", AccountJson: acct("in-bb")}}})
	}
	return ops
}

func BenchmarkRebuild10kEntrances(b *testing.B) {
	m := NewCoreManager()
	defer m.Teardown()
	inb := twoInbounds(benchPort(b), benchPort(b))
	users := benchEntranceOps(benchUsersN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.Rebuild(inb, users); err != nil {
			b.Fatal(err)
		}
	}
}

// W28-a: the source allowlist transaction for 16 relays of 64 networks
// each (rendered on every Snapshot; nft runs only when it changes).
func BenchmarkNftScript16x64(b *testing.B) {
	filters := make([]*pb.SourceFilter, 16)
	for i := range filters {
		cidrs := make([]string, 64)
		for j := range cidrs {
			cidrs[j] = fmt.Sprintf("10.%d.%d.0/24", i, j)
		}
		filters[i] = &pb.SourceFilter{Port: uint32(20000 + i), Tcp: true, Udp: true, Cidrs: cidrs}
	}
	specs := specsOf(filters)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := nftScript(specs); err != nil {
			b.Fatal(err)
		}
	}
}

// R44: the agent's per-Snapshot cost of the same filters: normalize, ID
// and the request handed to the root updater (the file write excluded).
func BenchmarkSourceFilterRequest16x64(b *testing.B) {
	filters := make([]*pb.SourceFilter, 16)
	for i := range filters {
		cidrs := make([]string, 64)
		for j := range cidrs {
			cidrs[j] = fmt.Sprintf("10.%d.%d.0/24", i, j)
		}
		filters[i] = &pb.SourceFilter{Port: uint32(20000 + i), Tcp: true, Udp: true, Cidrs: cidrs}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		specs, err := normalizeFilters(specsOf(filters))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := json.Marshal(&filterRequest{Schema: filterSchema, ID: filterID(specs), Filters: specs}); err != nil {
			b.Fatal(err)
		}
	}
}

// Heap held by a running 10k-user instance (reported as heap-MB).
func BenchmarkInstanceHeap10k(b *testing.B) {
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		m := benchCore(b, benchUsersN)
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "heap-MB")
		m.Teardown()
	}
}

// A UserDelta rotating one user's credentials on a 10k-user instance.
func BenchmarkDeltaRotate1of10k(b *testing.B) {
	m := benchCore(b, benchUsersN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.ApplyUserOps([]*pb.UserOp{benchOp(i%benchUsersN, i+1)}); err != nil {
			b.Fatal(err)
		}
	}
}

// The 10 s traffic report: every user has counters.
func BenchmarkTrafficSnapshot10k(b *testing.B) {
	m := benchCore(b, benchUsersN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := m.TrafficSnapshot(); len(r.Users) != benchUsersN {
			b.Fatalf("report has %d users", len(r.Users))
		}
	}
}

// W1: the periodic report when no counter moved (steady state).
func BenchmarkTrafficChanges10kIdle(b *testing.B) {
	m := benchCore(b, benchUsersN)
	_ = m.TrafficChanges() // first report on the stream: complete
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := m.TrafficChanges(); r != nil {
			b.Fatalf("idle report has %d users", len(r.Users))
		}
	}
}

// W1: the periodic report when 10% of the users moved since the last one.
func BenchmarkTrafficChanges10kTenPct(b *testing.B) {
	m := benchCore(b, benchUsersN)
	_ = m.TrafficChanges()
	m.mu.Lock()
	ctrs := make([]*userCounters, 0, benchUsersN/10)
	for i := 0; i < benchUsersN; i += 10 {
		ctrs = append(ctrs, m.counted[benchUserID(i)])
	}
	m.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, c := range ctrs {
			c.up.Add(1)
		}
		b.StartTimer()
		if r := m.TrafficChanges(); len(r.Users) != len(ctrs) {
			b.Fatalf("report has %d users, want %d", len(r.GetUsers()), len(ctrs))
		}
	}
}

// State hash over 20k credentials (Hello / every Ack).
func BenchmarkStateHash10k(b *testing.B) {
	m := benchCore(b, benchUsersN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.StateHash(1)
	}
}

// Gate bookkeeping per proxied connection (admit + release) with 20k
// admissible identities, from many goroutines.
func BenchmarkGateAdmitRelease(b *testing.B) {
	m := benchCore(b, benchUsersN)
	g := m.gate
	type id struct {
		key  gateKey
		user *protocol.MemoryUser
	}
	g.mu.Lock()
	ids := make([]id, 0, len(g.allowed))
	for k, u := range g.allowed {
		ids = append(ids, id{k, u})
	}
	g.mu.Unlock()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(rand.Int63()))
		for pb.Next() {
			x := ids[r.Intn(len(ids))]
			c := &liveConn{cancel: func() {}}
			if _, ok := g.admit(x.key, x.user, c); !ok {
				b.Error("admissible identity refused")
				return
			}
			g.release(x.key, c)
		}
	})
}

// Heartbeat's connection count with 5k live dispatches.
func BenchmarkConnections5kLive(b *testing.B) {
	m := benchCore(b, benchUsersN)
	g := m.gate
	type id struct {
		key  gateKey
		user *protocol.MemoryUser
	}
	var ids []id
	g.mu.Lock()
	for k, u := range g.allowed {
		if len(ids) == 5000 {
			break
		}
		ids = append(ids, id{k, u})
	}
	g.mu.Unlock()
	for _, x := range ids {
		g.admit(x.key, x.user, &liveConn{cancel: func() {}})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Connections()
	}
}

// Speed limits (ratelimit.go): the per-chunk cost on a limited user's
// path (bucket reservation, never waiting at this rate). Unlimited users
// are never wrapped; their only cost is the limits lookup inside admit
// (BenchmarkGateAdmitRelease).
func BenchmarkLimitedWrite8k(b *testing.B) {
	lim := newUserLimit(1 << 50)
	w := &limitedWriter{Writer: buf.Discard, ctx: context.Background(), b: &lim.down}
	b.SetBytes(buf.Size)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			x := buf.New()
			x.Extend(buf.Size)
			if err := w.WriteMultiBuffer(buf.MultiBuffer{x}); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// benchEcho: a local TCP echo server for benchmarks.
func benchEcho(tb testing.TB) int {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// benchConnectCore: one VLESS user on two raw TCP inbounds.
func benchConnectCore(b *testing.B) (m *CoreManager, port int) {
	m = NewCoreManager()
	b.Cleanup(func() { m.Teardown() })
	port = benchPort(b)
	if _, err := m.Rebuild(twoInbounds(port, benchPort(b)), []*pb.UserOp{vlessUser(benchUserID(1), "in-a", benchUserID(1))}); err != nil {
		b.Fatal(err)
	}
	return m, port
}

// benchConnectEcho: per-connection cost through the agent's xray (handshake,
// dispatch through the gate and router, one 64-byte round trip, close).
func benchConnectEcho(b *testing.B, port int) {
	echo := benchEcho(b)
	msg := string(make([]byte, 64))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := vlessDial(port, benchUserID(1), echo)
		if err != nil {
			b.Fatal(err)
		}
		if err := c.echo(msg); err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}

// A new connection: VLESS handshake + one round trip.
func BenchmarkConnectEcho(b *testing.B) {
	_, port := benchConnectCore(b)
	benchConnectEcho(b, port)
}
