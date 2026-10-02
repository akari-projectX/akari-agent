package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if m.swapTotal != 1048572*1024 || m.swapUsed != (1048572-786428)*1024 {
		t.Fatalf("%+v", m)
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
	tcp, udp := parseSockstat(fixture(t, "net/sockstat"))
	tcp6, udp6 := parseSockstat(fixture(t, "net/sockstat6"))
	if tcp != 120 || udp != 8 || tcp6 != 30 || udp6 != 4 {
		t.Fatalf("%d %d %d %d", tcp, udp, tcp6, udp6)
	}
	if got := parseStatusRSS(fixture(t, "self/status")); got != 54321*1024 {
		t.Fatalf("%d", got)
	}
	if got := parseStatusRSS([]byte("Name: x\n")); got != 0 {
		t.Fatalf("%d", got)
	}
}

func TestRate(t *testing.T) {
	if got := rate(1000, 3000, 2*time.Second); got != 1000 {
		t.Fatalf("%d", got)
	}
	if got := rate(3000, 1000, time.Second); got != 0 {
		t.Fatalf("reset must be 0, got %d", got)
	}
	if got := rate(1, 2, 0); got != 0 {
		t.Fatalf("%d", got)
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
	if m.NetInterface != "ens5" || m.NetRxBytesPerSec != 0 || m.NetTxBytesPerSec != 0 {
		t.Fatalf("first sample has no rate: %+v", m)
	}
	if cpu1 <= 0 || cpu1 >= 100 || mem.total == 0 || m.CpuCount != 2 || m.Load1 != 0.52 {
		t.Fatalf("cpu %v mem %+v m %+v", cpu1, mem, m)
	}
	if m.DiskUsedBytes != 30<<30 || m.DiskTotalBytes != 80<<30 || m.TcpSockets != 150 || m.UdpSockets != 12 ||
		m.ProcessRssBytes != 54321*1024 || m.NetRxBytesTotal != 98765432100 {
		t.Fatalf("%+v", m)
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
	cpu2, _, m2 := s.sample()
	if m2.NetRxBytesPerSec != 1_000_000 || m2.NetTxBytesPerSec != 100_000 {
		t.Fatalf("rates %+v", m2)
	}
	if math.Abs(cpu2-50) > 1e-9 {
		t.Fatalf("cpu %v", cpu2)
	}

	// Counter reset (interface re-created): rate 0, not a huge number.
	write("net/dev", "98780432100", "5")
	now = now.Add(15 * time.Second)
	if _, _, m3 := s.sample(); m3.NetRxBytesPerSec != 0 {
		t.Fatalf("reset rate %d", m3.NetRxBytesPerSec)
	}
}

func TestSamplerMissingProc(t *testing.T) {
	s := &sampler{fs: procFS{root: t.TempDir()}, statfs: func(string) (uint64, uint64, bool) { return 0, 0, false }, now: time.Now}
	cpu, mem, m := s.sample()
	if cpu != 0 || mem.total != 0 || m.NetInterface != "" || m.TcpSockets != 0 {
		t.Fatalf("%v %+v %+v", cpu, mem, m)
	}
}

// Online users = distinct emails with at least one live dispatch, over all
// inbounds.
func TestGateLiveStats(t *testing.T) {
	g := &gateDispatcher{live: map[gateKey]map[*liveConn]struct{}{
		{tag: "a", email: "u1"}: {&liveConn{}: {}, &liveConn{}: {}},
		{tag: "b", email: "u1"}: {&liveConn{}: {}},
		{tag: "a", email: "u2"}: {&liveConn{}: {}},
	}}
	if c, u := g.LiveStats(); c != 4 || u != 2 {
		t.Fatalf("conns %d users %d", c, u)
	}
	if c, u := (&gateDispatcher{live: map[gateKey]map[*liveConn]struct{}{}}).LiveStats(); c != 0 || u != 0 {
		t.Fatalf("%d %d", c, u)
	}
	var m CoreManager
	if c, u := m.LiveStats(); c != 0 || u != 0 {
		t.Fatalf("no instance: %d %d", c, u)
	}
}
