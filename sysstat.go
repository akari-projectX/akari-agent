package main

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"akari/agent/pb"
)

// Machine status for Heartbeat (W11): plain reads of Linux /proc files and
// statfs("/"), no cgo, no subprocesses. Every reader is a pure parser over
// the file's bytes (fixtures in sysstat_test.go); a file that cannot be
// read leaves its fields at 0. On other systems everything reads 0.

// procFS reads files below a /proc root (tests point it at fixtures).
type procFS struct{ root string }

func (p procFS) read(name string) []byte {
	b, err := os.ReadFile(filepath.Join(p.root, name))
	if err != nil {
		return nil
	}
	return b
}

// cpuTimes are the aggregate jiffies of the "cpu" line of /proc/stat.
type cpuTimes struct{ idle, total uint64 }

// parseCPUStat reads the aggregate "cpu" line (idle = idle + iowait;
// total = user..steal, guest time is already inside user/nice) and counts
// the per-CPU "cpuN" lines.
func parseCPUStat(b []byte) (cpuTimes, int, bool) {
	var t cpuTimes
	found := false
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			n++
			continue
		}
		if len(f) < 5 {
			return cpuTimes{}, 0, false
		}
		// user nice system idle iowait irq softirq steal [guest guest_nice]
		for i := 1; i < len(f) && i <= 8; i++ {
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return cpuTimes{}, 0, false
			}
			t.total += v
			if i == 4 || i == 5 {
				t.idle += v
			}
		}
		found = true
	}
	return t, n, found
}

// cpuPercent between two samples (0..100); 0 when nothing elapsed.
func cpuPercent(prev, cur cpuTimes) float64 {
	if cur.total <= prev.total || cur.idle < prev.idle {
		return 0
	}
	dt := float64(cur.total - prev.total)
	di := float64(cur.idle - prev.idle)
	if di > dt {
		return 0
	}
	return (dt - di) / dt * 100
}

func parseLoadavg(b []byte) (l1, l5, l15 float64, ok bool) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if l1, err = strconv.ParseFloat(f[0], 64); err != nil {
		return 0, 0, 0, false
	}
	if l5, err = strconv.ParseFloat(f[1], 64); err != nil {
		return 0, 0, 0, false
	}
	if l15, err = strconv.ParseFloat(f[2], 64); err != nil {
		return 0, 0, 0, false
	}
	// ParseFloat also takes "NaN", "Inf" and signs: never a load average.
	for _, v := range []float64{l1, l5, l15} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return 0, 0, 0, false
		}
	}
	return l1, l5, l15, true
}

// memInfo from /proc/meminfo, bytes. used = total - available (what
// free(1) and htop call used; MemAvailable exists since Linux 3.14, older
// kernels fall back to free + buffers + cached).
type memInfo struct {
	total, used, swapTotal, swapUsed uint64
}

func parseMeminfo(b []byte) memInfo {
	kv := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v = kib(v)
		}
		kv[name] = v
	}
	var m memInfo
	m.total = kv["MemTotal"]
	avail, ok := kv["MemAvailable"]
	if !ok {
		avail = satAdd(satAdd(kv["MemFree"], kv["Buffers"]), kv["Cached"])
	}
	if avail <= m.total {
		m.used = m.total - avail
	}
	m.swapTotal = kv["SwapTotal"]
	if free := kv["SwapFree"]; free <= m.swapTotal {
		m.swapUsed = m.swapTotal - free
	}
	return m
}

// kib: kB (KiB) to bytes, saturating instead of wrapping.
func kib(v uint64) uint64 {
	if v > math.MaxUint64/1024 {
		return math.MaxUint64
	}
	return v * 1024
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// parseDefaultRoute4: the interface of the default route in
// /proc/net/route (destination and mask 0, flag RTF_UP), lowest metric.
func parseDefaultRoute4(b []byte) string {
	best, bestMetric := "", uint64(1<<63)
	sc := bufio.NewScanner(bytes.NewReader(b))
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		metric, err := strconv.ParseUint(f[6], 10, 64)
		if err != nil {
			continue
		}
		if metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	return best
}

// parseDefaultRoute6: the interface of the ::/0 route in
// /proc/net/ipv6_route (lowest metric; "lo" entries, i.e. unreachable
// defaults, are skipped).
func parseDefaultRoute6(b []byte) string {
	best, bestMetric := "", uint64(1<<63)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// dest plen src splen nexthop metric refcnt use flags iface
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		metric, err := strconv.ParseUint(f[5], 16, 64)
		if err != nil {
			continue
		}
		if metric < bestMetric {
			best, bestMetric = f[9], metric
		}
	}
	return best
}

type ifCounters struct{ rx, tx uint64 }

// parseNetDev: receive/transmit byte counters per interface.
func parseNetDev(b []byte) map[string]ifCounters {
	out := map[string]ifCounters{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		// rx: bytes packets errs drop fifo frame compressed multicast; tx: bytes ...
		if len(f) < 16 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[strings.TrimSpace(name)] = ifCounters{rx: rx, tx: tx}
	}
	return out
}

// busiestInterface: fallback when no default route is found.
func busiestInterface(devs map[string]ifCounters) string {
	best, bestBytes := "", uint64(0)
	for name, c := range devs {
		if name == "lo" {
			continue
		}
		if t := c.rx + c.tx; t > bestBytes || (t == bestBytes && name < best) {
			best, bestBytes = name, t
		}
	}
	return best
}

// parseSockstat: sockets in use from /proc/net/sockstat ("TCP: inuse N",
// "UDP: inuse N") or sockstat6 ("TCP6: inuse N", "UDP6: inuse N").
func parseSockstat(b []byte) (tcp, udp uint32) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "inuse" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		switch f[0] {
		case "TCP:", "TCP6:":
			tcp += uint32(v)
		case "UDP:", "UDP6:":
			udp += uint32(v)
		}
	}
	return tcp, udp
}

// parseStatusRSS: VmRSS of /proc/self/status, bytes.
func parseStatusRSS(b []byte) uint64 {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "VmRSS:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return 0
		}
		if len(f) > 1 && f[1] == "kB" {
			v = kib(v)
		}
		return v
	}
	return 0
}

// rate per second between two counter readings; 0 on a reset/wrap or when
// no time passed.
func rate(prev, cur uint64, dt time.Duration) uint64 {
	if cur < prev || dt <= 0 {
		return 0
	}
	return uint64(float64(cur-prev) / dt.Seconds())
}

// sampler keeps the previous CPU and interface readings to turn counters
// into rates. Not safe for concurrent use (the heartbeat loop owns one).
type sampler struct {
	fs     procFS
	statfs func(path string) (used, total uint64, ok bool)
	now    func() time.Time

	prevCPU   cpuTimes
	havePrev  bool
	prevIface string
	prevNet   ifCounters
	prevAt    time.Time
}

func newSampler() *sampler {
	return &sampler{fs: procFS{root: "/proc"}, statfs: diskUsage, now: time.Now}
}

// sample: CPU % since the previous call (since boot on the first), memory,
// and the full NodeMetrics (minus the agent-side fields the caller fills:
// online users, xray version).
func (s *sampler) sample() (cpuPct float64, mem memInfo, m *pb.NodeMetrics) {
	m = &pb.NodeMetrics{}
	if cur, n, ok := parseCPUStat(s.fs.read("stat")); ok {
		prev := s.prevCPU
		if !s.havePrev {
			prev = cpuTimes{}
		}
		cpuPct = cpuPercent(prev, cur)
		s.prevCPU, s.havePrev = cur, true
		m.CpuCount = uint32(n)
	}
	if l1, l5, l15, ok := parseLoadavg(s.fs.read("loadavg")); ok {
		m.Load1, m.Load5, m.Load15 = l1, l5, l15
	}
	mem = parseMeminfo(s.fs.read("meminfo"))
	m.SwapUsedBytes, m.SwapTotalBytes = mem.swapUsed, mem.swapTotal
	if used, total, ok := s.statfs("/"); ok {
		m.DiskUsedBytes, m.DiskTotalBytes = used, total
	}

	devs := parseNetDev(s.fs.read("net/dev"))
	iface := parseDefaultRoute4(s.fs.read("net/route"))
	if _, ok := devs[iface]; !ok {
		iface = parseDefaultRoute6(s.fs.read("net/ipv6_route"))
	}
	if _, ok := devs[iface]; !ok {
		iface = busiestInterface(devs)
	}
	now := s.now()
	if c, ok := devs[iface]; ok {
		m.NetInterface = iface
		m.NetRxBytesTotal, m.NetTxBytesTotal = c.rx, c.tx
		if iface == s.prevIface && !s.prevAt.IsZero() {
			dt := now.Sub(s.prevAt)
			m.NetRxBytesPerSec = rate(s.prevNet.rx, c.rx, dt)
			m.NetTxBytesPerSec = rate(s.prevNet.tx, c.tx, dt)
		}
		s.prevIface, s.prevNet, s.prevAt = iface, c, now
	} else {
		s.prevIface, s.prevAt = "", time.Time{}
	}

	tcp4, udp4 := parseSockstat(s.fs.read("net/sockstat"))
	tcp6, udp6 := parseSockstat(s.fs.read("net/sockstat6"))
	m.TcpSockets, m.UdpSockets = tcp4+tcp6, udp4+udp6
	m.ProcessRssBytes = parseStatusRSS(s.fs.read("self/status"))
	return cpuPct, mem, m
}
