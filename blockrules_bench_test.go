package main

// W29 block rules: costs with the per-node switch on (results in the agent
// PR and akari-panel/docs/PERF.md "W29"). With the switch off the router
// wrapper is one atomic load (BenchmarkPickRouteOff vs Base) and the xray
// config is byte-identical (TestBlockSniffingConfig).

import (
	"fmt"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
)

// benchBlockPolicy: the size of the panel's built-in rule sets (440 tracker
// and 143 Thunder/PT domains, the BitTorrent protocol) plus a 1000-line
// custom domain rule and a 1000-line custom IP rule.
func benchBlockPolicy(tags []string, version string) *pb.BlockPolicy {
	dom := func(n int, f string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(f, i)
		}
		return out
	}
	cidrs := make([]string, 1000)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("198.%d.%d.0/24", 18+i/256, i%256)
	}
	return &pb.BlockPolicy{InboundTags: tags, Version: version, Rules: []*pb.BlockRule{
		{Id: 1, Protocols: []string{"bittorrent"}},
		{Id: 2, Domains: dom(440, "domain:tracker%d.example")},
		{Id: 3, Domains: dom(143, "full:pt%d.example")},
		{Id: 4, Domains: append(dom(990, "domain:custom%d.example"), dom(10, "keyword:torrent%d")...)},
		{Id: 5, Cidrs: cidrs},
	}}
}

func benchPick(b *testing.B, on bool, host string) {
	m := NewCoreManager()
	b.Cleanup(func() { m.Teardown() })
	if _, err := m.Rebuild(twoInbounds(benchPort(b), benchPort(b)), nil); err != nil {
		b.Fatal(err)
	}
	if on {
		if err := m.SetBlockPolicy(benchBlockPolicy([]string{"in-a", "in-b"}, "bench")); err != nil {
			b.Fatal(err)
		}
	}
	ctx := routingCtxFor(host, "in-a")
	r := m.gate.blocks
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.PickRoute(ctx)
	}
}

// The base router alone (what xray's dispatcher asks without the wrapper).
func BenchmarkPickRouteBase(b *testing.B) {
	m := NewCoreManager()
	b.Cleanup(func() { m.Teardown() })
	if _, err := m.Rebuild(twoInbounds(benchPort(b), benchPort(b)), nil); err != nil {
		b.Fatal(err)
	}
	ctx := routingCtxFor("www.example.com", "in-a")
	r := m.gate.blocks.base
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.PickRoute(ctx)
	}
}

func BenchmarkPickRouteOff(b *testing.B)    { benchPick(b, false, "www.example.com") }
func BenchmarkPickRouteOnMiss(b *testing.B) { benchPick(b, true, "www.example.com") }
func BenchmarkPickRouteOnHit(b *testing.B)  { benchPick(b, true, "a.tracker439.example") }

// A rule-content change: compile and swap the router (no handler change).
func BenchmarkBlockPolicySwap(b *testing.B) {
	m := NewCoreManager()
	b.Cleanup(func() { m.Teardown() })
	if _, err := m.Rebuild(twoInbounds(benchPort(b), benchPort(b)), nil); err != nil {
		b.Fatal(err)
	}
	tags := []string{"in-a", "in-b"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.SetBlockPolicy(benchBlockPolicy(tags, fmt.Sprint(i))); err != nil {
			b.Fatal(err)
		}
	}
}

// Resident cost of the compiled policy (heap in use after GC, with the
// policy vs without).
func BenchmarkBlockPolicyHeap(b *testing.B) {
	m := NewCoreManager()
	b.Cleanup(func() { m.Teardown() })
	if _, err := m.Rebuild(twoInbounds(benchPort(b), benchPort(b)), nil); err != nil {
		b.Fatal(err)
	}
	heap := func() uint64 {
		var s runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&s)
		return s.HeapInuse
	}
	var total int64
	for i := 0; i < b.N; i++ {
		before := heap()
		if err := m.SetBlockPolicy(benchBlockPolicy([]string{"in-a", "in-b"}, fmt.Sprint(i))); err != nil {
			b.Fatal(err)
		}
		total += int64(heap()) - int64(before)
		if err := m.SetBlockPolicy(&pb.BlockPolicy{}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(total)/float64(b.N), "heap-B")
}

// Report bandwidth: Heartbeat.block with every rule hit (35 rules = the 3
// built-in sets and the 32 custom maximum), every 15 s heartbeat; and the switch off.
func BenchmarkBlockStatsSize(b *testing.B) {
	s := &pb.BlockStats{Epoch: "0123456789abcdef", Applied: "0123456789ab"}
	for i := 0; i < 35; i++ {
		s.Hits = append(s.Hits, &pb.BlockHits{RuleId: uint64(i + 1), Hits: 1 << 40})
	}
	var n int
	for i := 0; i < b.N; i++ {
		n = proto.Size(&pb.Heartbeat{Block: s})
	}
	b.ReportMetric(float64(n), "bytes/heartbeat")
	// Switch off (an empty policy received, no hits): the epoch only.
	b.ReportMetric(float64(proto.Size(&pb.Heartbeat{Block: &pb.BlockStats{Epoch: s.Epoch}})), "off-bytes/heartbeat")
}

// A new connection with the switch on (sniffing + the full policy, not
// matching): compare with BenchmarkConnectEcho.
func BenchmarkConnectEchoBlockOn(b *testing.B) {
	m, port := benchConnectCore(b)
	if err := m.SetBlockPolicy(benchBlockPolicy([]string{"in-a"}, "bench")); err != nil {
		b.Fatal(err)
	}
	benchConnectEcho(b, port)
}
