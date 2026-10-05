package main

// Unit tests of the gate's bookkeeping and the rate limiter's edge cases
// (no xray instance: the paths that end before the inner dispatcher).
// End-to-end revocation through real xray clients is in core_test.go and
// the canaries.

import (
	"context"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newBareGate() *gateDispatcher { return newGate() }

// liveFor registers a tracked dispatch for key as user (what Dispatch /
// DispatchLink do) and returns it with a channel closed on cancel and the
// client-side reader of its link.
func liveFor(t *testing.T, g *gateDispatcher, key gateKey, user *protocol.MemoryUser) (*liveConn, <-chan struct{}, *pipe.Reader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, w := pipe.New()
	c := &liveConn{cancel: cancel, link: &transport.Link{Reader: r, Writer: w}}
	if _, ok := g.admit(key, user, c); !ok {
		t.Fatalf("admit %v refused", key)
	}
	return c, ctx.Done(), r
}

func cancelled(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// Rotation (Allow with a new *MemoryUser for the key) kills the key's live
// links and refuses the old identity from then on; re-allowing the same
// pointer keeps them (W9: same-credential re-add reuses the pointer).
func TestGateAllowRotationKillsOnlyThatKey(t *testing.T) {
	g := newBareGate()
	a := gateKey{tag: "in", email: "a"}
	b := gateKey{tag: "in", email: "b"}
	ua, ua2, ub := &protocol.MemoryUser{Email: "a"}, &protocol.MemoryUser{Email: "a"}, &protocol.MemoryUser{Email: "b"}
	g.Allow(a, ua)
	g.Allow(b, ub)
	_, doneA, readerA := liveFor(t, g, a, ua)
	_, doneB, _ := liveFor(t, g, b, ub)
	if g.LiveTotal() != 2 {
		t.Fatalf("live %d", g.LiveTotal())
	}
	if c, u := g.LiveStats(); c != 2 || u != 2 {
		t.Fatalf("stats %d %d", c, u)
	}
	g.Allow(a, ua) // same identity: nothing happens
	select {
	case <-doneA:
		t.Fatal("re-allowing the same user killed its link")
	default:
	}
	g.Allow(a, ua2) // rotated credential
	if !cancelled(doneA) {
		t.Fatal("rotation left the old identity's dispatch running")
	}
	if _, err := readerA.ReadMultiBuffer(); err == nil {
		t.Fatal("killed link still readable")
	}
	if g.Live(a) != 0 || g.Live(b) != 1 {
		t.Fatalf("live a=%d b=%d", g.Live(a), g.Live(b))
	}
	select {
	case <-doneB:
		t.Fatal("another key's link was killed")
	default:
	}
	if _, ok := g.admit(a, ua, &liveConn{cancel: func() {}}); ok {
		t.Fatal("old identity admitted after rotation")
	}
	if n := g.Revoke(b); n != 1 || !cancelled(doneB) {
		t.Fatalf("revoke closed %d", n)
	}
	if g.LiveTotal() != 0 {
		t.Fatalf("live %d after revoke", g.LiveTotal())
	}
}

// Close (instance teardown) kills everything and forgets every identity.
func TestGateCloseKillsAll(t *testing.T) {
	g := newBareGate()
	k := gateKey{tag: "in", email: "a"}
	u := &protocol.MemoryUser{Email: "a"}
	g.Allow(k, u)
	_, done1, _ := liveFor(t, g, k, u)
	_, done2, _ := liveFor(t, g, k, u)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if !cancelled(done1) || !cancelled(done2) || g.LiveTotal() != 0 {
		t.Fatal("close left dispatches running")
	}
	if _, ok := g.admit(k, u, &liveConn{cancel: func() {}}); ok {
		t.Fatal("identity survived close")
	}
}

// Managed dispatches that are refused never reach the inner dispatcher
// (a bare gate has none: reaching it would panic) and leave no entry.
func TestGateRefusesBeforeInnerDispatcher(t *testing.T) {
	g := newBareGate()
	u := &protocol.MemoryUser{Email: "a"}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "in", User: u})
	dest := xnet.TCPDestination(xnet.LocalHostIP, 80)
	if _, err := g.Dispatch(ctx, xnet.Destination{}); err == nil {
		t.Fatal("invalid destination dispatched")
	}
	if _, err := g.Dispatch(ctx, dest); !errors.Is(err, errRevoked) {
		t.Fatalf("unknown identity: %v", err)
	}
	r, w := pipe.New()
	if err := g.DispatchLink(ctx, dest, &transport.Link{Reader: r, Writer: w}); !errors.Is(err, errRevoked) {
		t.Fatalf("unknown identity (link): %v", err)
	}
	g.Allow(gateKey{tag: "in", email: "a"}, &protocol.MemoryUser{Email: "a"})
	if _, err := g.Dispatch(ctx, dest); !errors.Is(err, errRevoked) {
		t.Fatalf("other pointer for the key admitted: %v", err)
	}
	if g.LiveTotal() != 0 {
		t.Fatalf("refused dispatch left %d entries", g.LiveTotal())
	}
	if k, _, ok := identity(session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "in"})); ok {
		t.Fatalf("inbound without a user treated as managed: %v", k)
	}
}

// costNanos saturates when the quotient exceeds int64 even though the
// 128-bit division itself does not overflow; reserve saturates tat.
func TestRateLimitSaturation(t *testing.T) {
	if got := costNanos(1<<63+1, 1_000_000_000); got != math.MaxInt64 {
		t.Fatalf("costNanos = %d", got)
	}
	var b bucket
	b.rate.Store(1)
	now := int64(100 * 24 * time.Hour) // past the 64 KiB burst at 1 B/s
	if d := b.reserve(1<<40, now); d <= 0 {
		t.Fatalf("huge reservation not delayed: %v", d)
	}
	if b.tat != math.MaxInt64 {
		t.Fatalf("tat %d, want saturated", b.tat)
	}
	if d := b.reserve(1<<40, now); d <= 0 {
		t.Fatal("saturated bucket stopped pacing")
	}
	// Unlimited and empty reservations never wait.
	var free bucket
	if free.reserve(1<<40, now) != 0 || b.reserve(0, now) != 0 {
		t.Fatal("unlimited/empty reservation delayed")
	}
}

type errReader struct {
	mb  buf.MultiBuffer
	err error
	cnt int
}

func (e *errReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	e.cnt++
	mb := e.mb
	e.mb = nil
	return mb, e.err
}

func (e *errReader) Interrupt()   { e.err = io.ErrClosedPipe }
func (e *errReader) Close() error { e.err = io.ErrClosedPipe; return nil }

type failWriter struct{ calls int }

func (f *failWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	f.calls++
	buf.ReleaseMulti(mb)
	return io.ErrShortWrite
}

func (f *failWriter) Interrupt()   {}
func (f *failWriter) Close() error { return nil }

// The limited wrappers pass errors through unchanged: an empty read with
// an error, data together with an error (the data first, then the error),
// a cancelled wait (buffered data released), and a failing inner write.
func TestLimitedWrappersErrors(t *testing.T) {
	lim := newUserLimit(1 << 30)
	ctx := context.Background()
	r := &limitedReader{Reader: &errReader{err: io.ErrUnexpectedEOF}, ctx: ctx, b: &lim.up}
	if mb, err := r.ReadMultiBuffer(); !mb.IsEmpty() || err != io.ErrUnexpectedEOF {
		t.Fatalf("empty read: %v %v", mb, err)
	}
	inner := &errReader{mb: buf.MergeBytes(nil, []byte("tail")), err: io.EOF}
	r = &limitedReader{Reader: inner, ctx: ctx, b: &lim.up}
	mb, err := r.ReadMultiBuffer()
	if mb.String() != "tail" || err != io.EOF {
		t.Fatalf("data+error: %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	r.Interrupt()
	if inner.err != io.ErrClosedPipe || r.Close() != nil {
		t.Fatal("Interrupt/Close not passed through")
	}
	// A wait cut short by the context: the read fails, nothing is kept.
	slow := newUserLimit(1000)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_ = slow.up.reserve(limitBurstMin, monoNanos()) // spend the free burst
	big := buf.MergeBytes(nil, make([]byte, 3*limitChunk))
	r = &limitedReader{Reader: &errReader{mb: big}, ctx: cctx, b: &slow.up}
	if _, err := r.ReadMultiBuffer(); err == nil {
		t.Fatal("cancelled wait read succeeded")
	}
	if !r.pending.IsEmpty() {
		t.Fatal("pending data kept after a cancelled wait")
	}
	fw := &failWriter{}
	w := &limitedWriter{Writer: fw, ctx: ctx, b: &lim.down}
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 3*limitChunk))); err != io.ErrShortWrite || fw.calls != 1 {
		t.Fatalf("inner write error: %v after %d calls", err, fw.calls)
	}
	w.Interrupt()
	if w.Close() != nil {
		t.Fatal("Close not passed through")
	}
}

// W28-a (protocol 7): a user on two entrances ("u" on the direct inbound,
// "u#1" on a relay's derived inbound) is one account: one shared limit
// that stays while either op carries it, one online user; a limit that
// appears closes the live dispatches of both; another account is separate.
func TestAccountSharesLimitAndOnlineCount(t *testing.T) {
	if accountOf("u#1") != "u" || accountOf("u") != "u" || accountOf("u#1#2") != "u" {
		t.Fatal("accountOf")
	}
	g := newBareGate()
	d := gateKey{tag: "direct", email: "u"}
	r := gateKey{tag: "e1", email: "u#1"}
	o := gateKey{tag: "direct", email: "v"}
	ud, ur, uo := &protocol.MemoryUser{Email: "u"}, &protocol.MemoryUser{Email: "u#1"}, &protocol.MemoryUser{Email: "v"}
	g.Allow(d, ud)
	g.Allow(r, ur)
	g.Allow(o, uo)
	_, doneD, _ := liveFor(t, g, d, ud)
	_, doneR, _ := liveFor(t, g, r, ur)
	_, doneO, _ := liveFor(t, g, o, uo)
	if c, u := g.LiveStats(); c != 3 || u != 2 {
		t.Fatalf("stats %d conns %d users, want 3 / 2 (u counted once)", c, u)
	}
	// A limit appears on one op: both of the account's dispatches close
	// (they were admitted unthrottled), the other account's do not.
	if n := g.SetLimit("u#1", 1000); n != 2 {
		t.Fatalf("closed %d, want 2", n)
	}
	if !cancelled(doneD) || !cancelled(doneR) {
		t.Fatal("the account's live dispatches survived the new limit")
	}
	select {
	case <-doneO:
		t.Fatal("another account was cut")
	default:
	}
	if g.Limit("u") != 1000 || g.Limit("u#1") != 1000 || g.Limit("v") != 0 {
		t.Fatal("the limit is not the account's")
	}
	// The second op carries the same limit: shared, nothing closed.
	if n := g.SetLimit("u", 1000); n != 0 {
		t.Fatalf("closed %d", n)
	}
	lim1, ok := g.admit(d, ud, &liveConn{cancel: func() {}})
	lim2, ok2 := g.admit(r, ur, &liveConn{cancel: func() {}})
	if !ok || !ok2 || lim1 == nil || lim1 != lim2 {
		t.Fatal("the two entrances do not share one limiter")
	}
	// One op drops it (REMOVE of the relay): the other still carries it.
	g.SetLimit("u#1", 0)
	if g.Limit("u") != 1000 {
		t.Fatal("removing one entrance dropped the account's limit")
	}
	g.SetLimit("u", 0)
	if g.Limit("u") != 0 || len(g.limits) != 0 || len(g.limited) != 0 {
		t.Fatal("the last op left a limit behind")
	}
	// Dropping a limit nobody carried is a no-op.
	g.SetLimit("w", 0)
}
