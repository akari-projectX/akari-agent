package main

// M2-6: agent overhead at the M2 target scale (10k users per node, two
// inbounds each, like the panel's bench data set). Results are recorded in
// akari-panel/docs/PERF.md.
//
//	go test -run '^$' -bench . -benchmem -benchtime 5x ./...      (quick)
//	go test -run '^$' -bench . -benchmem ./...

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"testing"

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
			if !g.admit(x.key, x.user, c) {
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
