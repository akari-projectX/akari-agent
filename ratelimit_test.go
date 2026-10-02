package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"

	"akari/agent/pb"
)

func TestCostNanos(t *testing.T) {
	cases := []struct {
		n, r uint64
		want int64
	}{
		{1, 1, int64(time.Second)},
		{125000, 125000, int64(time.Second)}, // 1 Mbps, one second
		{1, 1_000_000_000, 1},
		{3, 2, int64(1500 * time.Millisecond)},
		{1 << 40, 1, int64(^uint64(0) >> 1)}, // saturates, never wraps
	}
	for _, c := range cases {
		if got := costNanos(c.n, c.r); got != c.want {
			t.Errorf("costNanos(%d, %d) = %d, want %d", c.n, c.r, got, c.want)
		}
	}
}

// The bucket admits one burst for free, then paces exactly at the rate,
// and an idle period refills at most one burst.
func TestBucketPacing(t *testing.T) {
	const r = 1 << 20 // 1 MiB/s: burst = r/5 = 209715 bytes
	var b bucket
	b.rate.Store(r)
	now := int64(10 * time.Second)
	burst := int(r / 5)
	if d := b.reserve(burst, now); d != 0 {
		t.Fatalf("first burst delayed %v", d)
	}
	// Next 1 MiB at the same instant: one second of debt.
	if d := b.reserve(r, now); d < 999*time.Millisecond || d > 1001*time.Millisecond {
		t.Fatalf("1 MiB after a full burst waits %v, want ~1s", d)
	}
	// Steady state: n bytes cost n/r after the backlog.
	if d := b.reserve(r/2, now); d < 1499*time.Millisecond || d > 1501*time.Millisecond {
		t.Fatalf("backlog not accumulated: %v", d)
	}
	// Long idle: only one burst is free again (no unbounded credit).
	later := now + int64(time.Hour)
	if d := b.reserve(burst, later); d != 0 {
		t.Fatalf("burst after idle delayed %v", d)
	}
	if d := b.reserve(r/10, later); d < 99*time.Millisecond || d > 101*time.Millisecond {
		t.Fatalf("idle accumulated more than one burst: %v", d)
	}
	// Unlimited: never waits, nothing booked.
	var u bucket
	if d := u.reserve(1<<30, now); d != 0 {
		t.Fatal("unlimited bucket waited")
	}
	// Rate changes apply to the next reservation.
	b.rate.Store(0)
	if d := b.reserve(1<<30, later); d != 0 {
		t.Fatal("rate 0 still paces")
	}
}

func TestBucketMinimumBurst(t *testing.T) {
	var b bucket
	b.rate.Store(125000) // 1 Mbps: r/5 < 64 KiB, so the burst is 64 KiB
	if d := b.reserve(limitBurstMin, 0); d != 0 {
		t.Fatalf("64 KiB burst delayed %v", d)
	}
	if d := b.reserve(125000, 0); d < 999*time.Millisecond || d > 1001*time.Millisecond {
		t.Fatalf("got %v", d)
	}
}

func TestBucketWaitHonoursContext(t *testing.T) {
	var b bucket
	b.rate.Store(1000)
	ctx, cancel := context.WithCancel(context.Background())
	_ = b.wait(ctx, limitBurstMin) // the free burst
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	if err := b.wait(ctx, 1_000_000); err == nil {
		t.Fatal("wait of ~1000s returned without error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation did not interrupt the wait")
	}
}

type sliceReader struct{ mbs []buf.MultiBuffer }

func (s *sliceReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(s.mbs) == 0 {
		return nil, io.EOF
	}
	mb := s.mbs[0]
	s.mbs = s.mbs[1:]
	return mb, nil
}

type countWriter struct{ n int32 }

func (c *countWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	c.n += mb.Len()
	buf.ReleaseMulti(mb)
	return nil
}

func TestLimitedReaderWriterPassData(t *testing.T) {
	lim := newUserLimit(1 << 30)
	ctx := context.Background()
	r := &limitedReader{Reader: &sliceReader{mbs: []buf.MultiBuffer{buf.MergeBytes(nil, []byte("abc"))}}, ctx: ctx, b: &lim.up}
	mb, err := r.ReadMultiBuffer()
	if err != nil || mb.String() != "abc" {
		t.Fatalf("read %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	if _, err := r.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("EOF not passed: %v", err)
	}
	cw := &countWriter{}
	w := &limitedWriter{Writer: cw, ctx: ctx, b: &lim.down}
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 5000))); err != nil || cw.n != 5000 {
		t.Fatalf("write %d %v", cw.n, err)
	}
	// A cancelled context fails a write that has to wait.
	slow := newUserLimit(1000)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	w = &limitedWriter{Writer: cw, ctx: cctx, b: &slow.down}
	_ = w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, limitBurstMin)))
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 5000))); err == nil {
		t.Fatal("cancelled write succeeded")
	}
}

// Big batches (pipes hand over hundreds of KiB) are passed on in chunks,
// so pacing never holds a whole batch; data, order and the trailing error
// are preserved.
func TestLimitedWrappersChunk(t *testing.T) {
	big := make([]byte, 100<<10)
	for i := range big {
		big[i] = byte(i)
	}
	lim := newUserLimit(1 << 40)
	r := &limitedReader{Reader: &sliceReader{mbs: []buf.MultiBuffer{buf.MergeBytes(nil, big)}}, ctx: context.Background(), b: &lim.up}
	var got []byte
	for {
		mb, err := r.ReadMultiBuffer()
		if mb.Len() > limitChunk {
			t.Fatalf("chunk of %d", mb.Len())
		}
		for _, x := range mb {
			got = append(got, x.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != string(big) {
		t.Fatalf("reader changed the data (%d bytes)", len(got))
	}
	cw := &chunkWriter{}
	w := &limitedWriter{Writer: cw, ctx: context.Background(), b: &lim.down}
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, big)); err != nil {
		t.Fatal(err)
	}
	if cw.max > limitChunk || cw.total != len(big) || cw.writes < 4 {
		t.Fatalf("writer chunks: max %d total %d writes %d", cw.max, cw.total, cw.writes)
	}
}

type chunkWriter struct{ max, total, writes int }

func (c *chunkWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int(mb.Len())
	c.writes++
	c.total += n
	if n > c.max {
		c.max = n
	}
	buf.ReleaseMulti(mb)
	return nil
}

// SetLimit: a new limit closes the user's live (unthrottled) dispatches on
// every inbound and nobody else's; changing or removing it keeps them.
func TestSetLimitTransitions(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	pa, pb2 := freePort(t), freePort(t)
	ua := vlessUser(userA, "in-a", idA)
	ua.InboundUsers = append(ua.InboundUsers, &pb.InboundUser{InboundTag: "in-b", Protocol: "vless",
		AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, idA)})
	if _, err := m.Rebuild(twoInbounds(pa, pb2), []*pb.UserOp{ua, vlessUser(userB, "in-a", idB)}); err != nil {
		t.Fatal(err)
	}
	ca1, err := vlessDial(pa, idA, echo)
	mustEcho(t, ca1, err, "a1")
	ca2, err := vlessDial(pb2, idA, echo)
	mustEcho(t, ca2, err, "a2")
	cb, err := vlessDial(pa, idB, echo)
	mustEcho(t, cb, err, "b")

	// The panel limits A (same credentials, new limit).
	ua.SpeedLimitBytesPerSec = 1 << 20
	if _, err := m.ApplyUserOps([]*pb.UserOp{ua}); err != nil {
		t.Fatal(err)
	}
	if !ca1.closedWithin(2*time.Second) || !ca2.closedWithin(2*time.Second) {
		t.Fatal("A's unthrottled connections survived the new limit")
	}
	if err := cb.echo("b still up"); err != nil {
		t.Fatalf("B's connection was touched: %v", err)
	}
	if got := m.gate.Limit(userA); got != 1<<20 {
		t.Fatalf("limit %d", got)
	}
	// Reconnect (throttled now); changing the limit keeps it.
	ca, err := vlessDial(pa, idA, echo)
	mustEcho(t, ca, err, "again")
	ua.SpeedLimitBytesPerSec = 2 << 20
	if _, err := m.ApplyUserOps([]*pb.UserOp{ua}); err != nil {
		t.Fatal(err)
	}
	mustEcho(t, ca, nil, "after change")
	ua.SpeedLimitBytesPerSec = 0
	if _, err := m.ApplyUserOps([]*pb.UserOp{ua}); err != nil {
		t.Fatal(err)
	}
	mustEcho(t, ca, nil, "after removal of the limit")
	if m.gate.Limit(userA) != 0 {
		t.Fatal("limit not removed")
	}
	// REMOVE clears it too.
	ua.SpeedLimitBytesPerSec = 5 << 20
	if _, err := m.ApplyUserOps([]*pb.UserOp{ua, {Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	if m.gate.Limit(userA) != 0 {
		t.Fatal("removed user kept a limit")
	}
}

// sinkSource serves raw TCP: the first byte selects "d" (send `n` bytes,
// then close) or "u" (read a u64be length and that many bytes, then answer
// with the byte count).
func sinkSource(t *testing.T, n int) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var cmd [1]byte
				if _, err := io.ReadFull(c, cmd[:]); err != nil {
					return
				}
				if cmd[0] == 'd' {
					_, _ = c.Write(make([]byte, n))
					return
				}
				var size [8]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				got, _ := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint64(size[:])))
				_, _ = c.Write(binary.BigEndian.AppendUint64(nil, uint64(got)))
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// download pulls n bytes through VLESS and returns how long it took.
func download(t *testing.T, inbound int, id string, dest, n int) time.Duration {
	t.Helper()
	c, err := vlessDial(inbound, id, dest)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte{'d'}); err != nil {
		t.Error(err)
		return 0
	}
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		t.Error(err)
		return 0
	}
	// Time to the last byte (xray closes the client side only after its
	// uplinkOnly grace, which is not throughput).
	got, err := io.CopyN(io.Discard, c.r, int64(n))
	if err != nil || got != int64(n) {
		t.Errorf("downloaded %d of %d: %v", got, n, err)
	}
	return time.Since(start)
}

// upload pushes n bytes through VLESS and returns the time until the
// destination confirmed them.
func upload(t *testing.T, inbound int, id string, dest, n int) time.Duration {
	t.Helper()
	c, err := vlessDial(inbound, id, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	msg := binary.BigEndian.AppendUint64([]byte{'u'}, uint64(n))
	if _, err := c.Write(append(msg, make([]byte, n)...)); err != nil {
		t.Fatal(err)
	}
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		t.Fatal(err)
	}
	var cnt [8]byte
	if _, err := io.ReadFull(c.r, cnt[:]); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(cnt[:]); got != uint64(n) {
		t.Fatalf("uploaded %d of %d", got, n)
	}
	return time.Since(start)
}

// expect asserts that `bytes` at `rate` (minus one burst) took about d.
func expectRate(t *testing.T, what string, d time.Duration, bytes, rate int) {
	t.Helper()
	burst := rate / 5
	if burst < limitBurstMin {
		burst = limitBurstMin
	}
	want := time.Duration(float64(bytes-burst) / float64(rate) * float64(time.Second))
	eff := float64(bytes) / d.Seconds()
	t.Logf("%s: %d bytes in %v = %.0f B/s (limit %d B/s, expected >= %v)", what, bytes, d, eff, rate, want)
	if d < want*95/100 {
		t.Errorf("%s faster than the limit allows: %v < %v", what, d, want)
	}
	if d > want*140/100+300*time.Millisecond {
		t.Errorf("%s much slower than the limit: %v vs %v", what, d, want)
	}
}

// A real VLESS client through a real xray instance: a limited user's
// download and upload run at the limit, the limit is shared by the user's
// concurrent connections across inbounds, and another (unlimited) user on
// the same node is not slowed.
func TestSpeedLimitThrottlesRealTraffic(t *testing.T) {
	const rate = 512 << 10 // 512 KiB/s = ~4.2 Mbps
	const n = 3 * rate / 2 // 768 KiB
	m := NewCoreManager()
	defer m.Teardown()
	ss := sinkSource(t, n)
	pa, pb2 := freePort(t), freePort(t)
	ua := vlessUser(userA, "in-a", idA)
	ua.InboundUsers = append(ua.InboundUsers, &pb.InboundUser{InboundTag: "in-b", Protocol: "vless",
		AccountJson: fmt.Sprintf(`{"flow":"","id":%q}`, idA)})
	ua.SpeedLimitBytesPerSec = rate
	if _, err := m.Rebuild(twoInbounds(pa, pb2), []*pb.UserOp{ua, vlessUser(userB, "in-a", idB)}); err != nil {
		t.Fatal(err)
	}

	expectRate(t, "download", download(t, pa, idA, ss, n), n, rate)
	t.Logf("unlimited upload %v", upload(t, pa, idB, ss, n))
	expectRate(t, "upload", upload(t, pa, idA, ss, n), n, rate)

	// Two concurrent downloads on two inbounds share one user budget.
	var wg sync.WaitGroup
	start := time.Now()
	for _, p := range []int{pa, pb2} {
		wg.Add(1)
		go func(p int) { defer wg.Done(); download(t, p, idA, ss, n/2) }(p)
	}
	wg.Wait()
	expectRate(t, "two connections", time.Since(start), n, rate)

	// The unlimited user is not throttled.
	if d := download(t, pa, idB, ss, n); d > time.Second {
		t.Errorf("unlimited user took %v for %d bytes", d, n)
	}
}
