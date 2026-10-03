package main

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "proc", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCPUStat(t *testing.T) {
	ct, n, ok := parseCPUStat(fixture(t, "stat"))
	if !ok || n != 2 {
		t.Fatalf("ok=%v n=%d", ok, n)
	}
	// user..steal; guest columns are already inside user/nice.
	if ct.total != 60377929 || ct.idle != 46845166 {
		t.Fatalf("got %+v", ct)
	}
	if _, _, ok := parseCPUStat([]byte("cpu 1 2\n")); ok {
		t.Fatal("short cpu line accepted")
	}
	if _, _, ok := parseCPUStat([]byte("cpu a b c d e\n")); ok {
		t.Fatal("garbage accepted")
	}
	if _, _, ok := parseCPUStat(nil); ok {
		t.Fatal("empty accepted")
	}
}

func TestCPUPercent(t *testing.T) {
	prev := cpuTimes{idle: 100, total: 200}
	if got := cpuPercent(prev, cpuTimes{idle: 175, total: 300}); math.Abs(got-25) > 1e-9 {
		t.Fatalf("got %v", got)
	}
	// No time passed, or counters went backwards: 0, never NaN/negative.
	for _, cur := range []cpuTimes{{idle: 100, total: 200}, {idle: 50, total: 300}, {idle: 400, total: 300}} {
		if got := cpuPercent(prev, cur); got != 0 {
			t.Fatalf("%+v -> %v", cur, got)
		}
	}
}

func TestParseLoadavg(t *testing.T) {
	l1, l5, l15, ok := parseLoadavg(fixture(t, "loadavg"))
	if !ok || l1 != 0.52 || l5 != 0.58 || l15 != 0.59 {
		t.Fatalf("%v %v %v %v", l1, l5, l15, ok)
	}
	if _, _, _, ok := parseLoadavg([]byte("x y z")); ok {
		t.Fatal("garbage accepted")
	}
}

func TestParseMeminfo(t *testing.T) {
	m := parseMeminfo(fixture(t, "meminfo"))
	if m.total != 2014204*1024 || m.used != (2014204-905312)*1024 {
		t.Fatalf("%+v", m)
	}
	if m.swapTotal != 1048572*1024 || m.swapUsed != (1048572-786428)*1024 || !m.hasMem || !m.hasSwap {
		t.Fatalf("%+v", m)
	}
	// W23: what the file lacks is unknown, not 0.
	if z := parseMeminfo(nil); z.hasMem || z.hasSwap {
		t.Fatalf("empty meminfo: %+v", z)
	}
	if z := parseMeminfo([]byte("MemTotal: 10 kB\n")); z.hasMem {
		t.Fatalf("no MemAvailable/MemFree: %+v", z)
	}
	if z := parseMeminfo([]byte("MemTotal: 1000 kB\nMemAvailable: 900 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")); !z.hasSwap || z.swapTotal != 0 {
		t.Fatalf("no swap is a known 0: %+v", z)
	}
	// Pre-3.14 kernels: no MemAvailable.
	old := parseMeminfo([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n"))
	if old.used != 600*1024 {
		t.Fatalf("%+v", old)
	}
	if z := parseMeminfo([]byte("MemTotal: 10 kB\nMemAvailable: 20 kB\n")); z.used != 0 {
		t.Fatalf("available > total must not wrap: %+v", z)
	}
}

func TestDefaultRoute(t *testing.T) {
	if got := parseDefaultRoute4(fixture(t, "net/route")); got != "ens5" {
		t.Fatalf("v4 %q", got)
	}
	if got := parseDefaultRoute6(fixture(t, "net/ipv6_route")); got != "ens6" {
		t.Fatalf("v6 %q", got)
	}
	if got := parseDefaultRoute4([]byte("Iface\tDestination\n")); got != "" {
		t.Fatalf("%q", got)
	}
	// A default route that is down does not count.
	down := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nens9\t00000000\t0100A8C0\t0002\t0\t0\t0\t00000000\n"
	if got := parseDefaultRoute4([]byte(down)); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestParseNetDevAndBusiest(t *testing.T) {
	d := parseNetDev(fixture(t, "net/dev"))
	if len(d) != 3 || d["ens5"] != (ifCounters{rx: 98765432100, tx: 12345678900}) || d["docker0"].tx != 400 {
		t.Fatalf("%+v", d)
	}
	if got := busiestInterface(d); got != "ens5" {
		t.Fatalf("%q", got)
	}
	if got := busiestInterface(map[string]ifCounters{"lo": {rx: 9}}); got != "" {
		t.Fatalf("loopback chosen: %q", got)
	}
}

func TestParseSockstatAndRSS(t *testing.T) {
	tcp, udp, ok4 := parseSockstat(fixture(t, "net/sockstat"))
	tcp6, udp6, ok6 := parseSockstat(fixture(t, "net/sockstat6"))
	if tcp != 120 || udp != 8 || tcp6 != 30 || udp6 != 4 || !ok4 || !ok6 {
		t.Fatalf("%d %d %d %d", tcp, udp, tcp6, udp6)
	}
	if _, _, ok := parseSockstat([]byte("sockets: used 3\n")); ok {
		t.Fatal("no TCP/UDP line is not a reading")
	}
	if got, ok := parseStatusRSS(fixture(t, "self/status")); !ok || got != 54321*1024 {
		t.Fatalf("%d", got)
	}
	if got, ok := parseStatusRSS([]byte("Name: x\n")); ok || got != 0 {
		t.Fatalf("%d", got)
	}
}

func TestRate(t *testing.T) {
	if got, ok := rate(1000, 3000, 2*time.Second); !ok || got != 1000 {
		t.Fatalf("%d", got)
	}
	if got, ok := rate(3000, 1000, time.Second); ok || got != 0 {
		t.Fatalf("reset must be unknown, got %d", got)
	}
	if _, ok := rate(1, 2, 0); ok {
		t.Fatal("no time passed")
	}
}

// copyTree copies the fixture /proc into a temp dir the test can modify.
func copyTree(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", "proc")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestSamplerRates(t *testing.T) {
	root := copyTree(t)
	now := time.Unix(1_700_000_000, 0)
	s := &sampler{
		fs:     procFS{root: root},
		statfs: func(string) (uint64, uint64, bool) { return 30 << 30, 80 << 30, true },
		now:    func() time.Time { return now },
	}
	cpu1, mem, m := s.sample()
	if m.NetInterface != "ens5" || m.NetRxBytesPerSec != nil || m.NetTxBytesPerSec != nil {
		t.Fatalf("first sample has no rate (unknown, not 0): %+v", m)
	}
	if cpu1 == nil || *cpu1 <= 0 || *cpu1 >= 100 || mem.total == 0 || m.GetCpuCount() != 2 || m.GetLoad1() != 0.52 {
		t.Fatalf("cpu %v mem %+v m %+v", cpu1, mem, m)
	}
	if m.GetDiskUsedBytes() != 30<<30 || m.GetDiskTotalBytes() != 80<<30 || m.GetTcpSockets() != 150 ||
		m.GetUdpSockets() != 12 || m.GetProcessRssBytes() != 54321*1024 || m.GetNetRxBytesTotal() != 98765432100 {
		t.Fatalf("%+v", m)
	}
	if hb := buildHeartbeat(s, agentStats{}, func() (time.Duration, bool) { return 0, false }); len(unavailableMetrics(hb)) != 0 {
		t.Fatalf("fixture /proc: everything readable, got unavailable %v", unavailableMetrics(hb))
	}

	// 15 s later: +15 MB in, +1.5 MB out, CPU 50% busy since.
	write := func(name, from, to string) {
		p := filepath.Join(root, name)
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), from) {
			t.Fatalf("%s: %q not found", name, from)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), from, to, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("net/dev", "98765432100", "98780432100")
	write("net/dev", "12345678900", "12347178900")
	write("stat", "cpu  10132153 290696 3084719 46828483", "cpu  10132653 290696 3084719 46828983")
	now = now.Add(15 * time.Second)
	// (buildHeartbeat above sampled at the same instant: no time passed,
	// no rate; it moved the previous reading, so sample again.)
	cpu2, _, m2 := s.sample()
	if m2.GetNetRxBytesPerSec() != 1_000_000 || m2.GetNetTxBytesPerSec() != 100_000 {
		t.Fatalf("rates %+v", m2)
	}
	if cpu2 == nil || math.Abs(*cpu2-50) > 1e-9 {
		t.Fatalf("cpu %v", cpu2)
	}

	// Counter reset (interface re-created): unknown, not a huge number.
	write("net/dev", "98780432100", "5")
	now = now.Add(15 * time.Second)
	if _, _, m3 := s.sample(); m3.NetRxBytesPerSec != nil {
		t.Fatalf("reset rate %d", m3.GetNetRxBytesPerSec())
	}
}

func TestSamplerMissingProc(t *testing.T) {
	s := &sampler{fs: procFS{root: t.TempDir()}, statfs: func(string) (uint64, uint64, bool) { return 0, 0, false }, now: time.Now}
	cpu, mem, m := s.sample()
	if cpu != nil || mem.hasMem || m.NetInterface != "" || m.TcpSockets != nil || m.Load1 != nil || m.CpuCount != nil ||
		m.DiskTotalBytes != nil || m.ProcessRssBytes != nil || m.NetRxBytesTotal != nil || m.SwapTotalBytes != nil {
		t.Fatalf("unreadable values must be unset (unknown), not 0: %v %+v %+v", cpu, mem, m)
	}
	hb := buildHeartbeat(s, agentStats{}, func() (time.Duration, bool) { return 0, false })
	if hb.CpuPercent != nil || hb.MemTotalBytes != nil || hb.MemUsedBytes != nil {
		t.Fatalf("%+v", hb)
	}
	want := []string{"cpu_percent", "memory", "cpu_count", "load", "swap", "disk", "net", "sockets", "process_rss"}
	if got := unavailableMetrics(hb); !slices.Equal(got, want) {
		t.Fatalf("unavailable %v", got)
	}
}

// W23: ProcSubset=pid (the pre-W23 unit) leaves only the per-process
// entries (/proc/self/...): everything machine-wide is unknown, the RSS is
// still read.
func TestSamplerPidOnlyProc(t *testing.T) {
	root := copyTree(t)
	for _, f := range []string{"stat", "loadavg", "meminfo", "net"} {
		if err := os.RemoveAll(filepath.Join(root, f)); err != nil {
			t.Fatal(err)
		}
	}
	s := &sampler{fs: procFS{root: root}, statfs: func(string) (uint64, uint64, bool) { return 1, 2, true }, now: time.Now}
	hb := buildHeartbeat(s, agentStats{}, func() (time.Duration, bool) { return 0, false })
	want := []string{"cpu_percent", "memory", "cpu_count", "load", "swap", "net", "sockets"}
	if got := unavailableMetrics(hb); !slices.Equal(got, want) {
		t.Fatalf("unavailable %v", got)
	}
	if hb.Metrics.GetProcessRssBytes() != 54321*1024 || hb.Metrics.GetDiskTotalBytes() != 2 {
		t.Fatalf("%+v", hb.Metrics)
	}
}

// Online users = distinct emails with at least one live dispatch, over all
// inbounds.
func TestGateLiveStats(t *testing.T) {
	g := newGate()
	u1, u2 := &protocol.MemoryUser{Email: "u1"}, &protocol.MemoryUser{Email: "u2"}
	a1, b1, a2 := gateKey{tag: "a", email: "u1"}, gateKey{tag: "b", email: "u1"}, gateKey{tag: "a", email: "u2"}
	g.Allow(a1, u1)
	g.Allow(b1, u1)
	g.Allow(a2, u2)
	admit := func(k gateKey, u *protocol.MemoryUser) *liveConn {
		c := &liveConn{cancel: func() {}}
		if _, ok := g.admit(k, u, c); !ok {
			t.Fatal("refused")
		}
		return c
	}
	want := func(conns, users int) {
		t.Helper()
		if c, u := g.LiveStats(); c != conns || u != users || g.LiveTotal() != conns {
			t.Fatalf("conns %d users %d, want %d %d", c, u, conns, users)
		}
		// The O(1) counters agree with a recount of the tracked set.
		g.mu.Lock()
		n, seen := 0, map[string]struct{}{}
		for k, cs := range g.live {
			n += len(cs)
			seen[k.email] = struct{}{}
		}
		g.mu.Unlock()
		if n != conns || len(seen) != users {
			t.Fatalf("recount %d/%d, counters %d/%d", n, len(seen), conns, users)
		}
	}
	want(0, 0)
	c1, c2, c3 := admit(a1, u1), admit(a1, u1), admit(b1, u1)
	c4 := admit(a2, u2)
	want(4, 2)
	g.release(a1, c1)
	want(3, 2)
	g.release(a1, c1) // double release: no change
	want(3, 2)
	g.Revoke(a1) // takes c2
	want(2, 2)
	g.release(a1, c2) // the relay ending after the revocation
	want(2, 2)
	g.release(b1, c3)
	want(1, 1)
	g.Allow(a2, &protocol.MemoryUser{Email: "u2"}) // rotation: c4 cut
	want(0, 0)
	g.release(a2, c4)
	want(0, 0)
	g.Allow(a1, u1)
	admit(a1, u1)
	admit(a2, g.allowed[a2])
	want(2, 2)
	_ = g.Close()
	want(0, 0)
	var m CoreManager
	if c, u := m.LiveStats(); c != 0 || u != 0 {
		t.Fatalf("no instance: %d %d", c, u)
	}
}
