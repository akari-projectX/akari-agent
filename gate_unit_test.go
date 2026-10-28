package main

// Unit tests of the gate's bookkeeping and the rate limiter's edge cases
// (no xray instance: the paths that end before the inner dispatcher).
// End-to-end revocation through real xray clients is in core_test.go and
// the canaries.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"sync"
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

// checkLiveIndex fails unless the gate's account index (liveKeys) is
// exactly live's keys grouped by account, each once: a key in
// live but not in the index would escape SetLimit's kill.
func checkLiveIndex(t *testing.T, g *gateDispatcher) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	indexed := 0
	for acc, ak := range g.liveKeys {
		if ak.more != nil && len(ak.more) == 0 {
			t.Errorf("liveKeys[%q] keeps an empty overflow set", acc)
		}
		if _, dup := ak.more[ak.first]; dup {
			t.Errorf("liveKeys[%q] holds %v twice", acc, ak.first)
		}
		for _, key := range ak.keys() {
			indexed++
			if accountOf(key.email) != acc {
				t.Errorf("key %v indexed under account %q", key, acc)
			}
			if len(g.live[key]) == 0 {
				t.Errorf("indexed key %v has no live dispatch", key)
			}
		}
	}
	for key := range g.live {
		ak, ok := g.liveKeys[accountOf(key.email)]
		_, inMore := ak.more[key]
		if !ok || (ak.first != key && !inMore) {
			t.Errorf("live key %v missing from liveKeys", key)
		}
	}
	if indexed != len(g.live) {
		t.Errorf("liveKeys holds %d keys, live %d", indexed, len(g.live))
	}
	if int(g.liveUsers.Load()) != len(g.liveKeys) {
		t.Errorf("liveUsers %d, liveKeys has %d accounts", g.liveUsers.Load(), len(g.liveKeys))
	}
}

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
	checkLiveIndex(t, g)
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
	checkLiveIndex(t, g)
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
	checkLiveIndex(t, g)
	if g.LiveTotal() != 0 {
		t.Fatalf("live %d after revoke", g.LiveTotal())
	}
}

// closeProbe is a client connection that reports its Close.
type closeProbe struct {
	net.Conn
	closed chan struct{}
}

func (c *closeProbe) Close() error {
	close(c.closed)
	return c.Conn.Close()
}

// A revoked client's connection is closed, not just its relay cut: the
// protocol handler that owns the socket closes it when its copy tasks end,
// and a handler stuck in xray's ActivityTimer self-deadlock never gets
// there (soak 2026-10-27). Revoke, rotation,
// a new limit and teardown all kill; each closes the connection.
func TestGateKillClosesTheClientConnection(t *testing.T) {
	user := &protocol.MemoryUser{Email: "a#1"}
	key := gateKey{tag: "e1", email: "a#1"}
	probe := func(g *gateDispatcher) (*closeProbe, *liveConn) {
		srv, cli := net.Pipe()
		t.Cleanup(func() { _ = srv.Close(); _ = cli.Close() })
		cp := &closeProbe{Conn: srv, closed: make(chan struct{})}
		r, w := pipe.New()
		c := &liveConn{cancel: func() {}, link: &transport.Link{Reader: r, Writer: w}, conn: cp}
		if _, ok := g.admit(key, user, c); !ok {
			t.Fatal("admit refused")
		}
		return cp, c
	}
	wasClosed := func(cp *closeProbe) bool {
		select {
		case <-cp.closed:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	for name, kill := range map[string]func(g *gateDispatcher){
		"revoke": func(g *gateDispatcher) { g.Revoke(key) },
		"rotate": func(g *gateDispatcher) { g.Allow(key, &protocol.MemoryUser{Email: "a#1"}) },
		"close":  func(g *gateDispatcher) { _ = g.Close() },
		"limit":  func(g *gateDispatcher) { g.SetLimit("a", 1<<20) },
	} {
		t.Run(name, func(t *testing.T) {
			g := newBareGate()
			g.Allow(key, user)
			cp, _ := probe(g)
			kill(g)
			checkLiveIndex(t, g)
			if !wasClosed(cp) {
				t.Fatal("the client connection of a killed dispatch stayed open")
			}
		})
	}
	t.Run("untouched", func(t *testing.T) {
		g := newBareGate()
		g.Allow(key, user)
		other := gateKey{tag: "e1", email: "b#1"}
		g.Allow(other, &protocol.MemoryUser{Email: "b#1"})
		cp, _ := probe(g)
		g.Revoke(other)
		select {
		case <-cp.closed:
			t.Fatal("another key's revocation closed this connection")
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// Close (instance teardown) kills everything and forgets every identity.
func TestGateCloseKillsAll(t *testing.T) {
	g := newBareGate()
	k := gateKey{tag: "in", email: "a"}
	u := &protocol.MemoryUser{Email: "a"}
	g.Allow(k, u)
	_, done1, _ := liveFor(t, g, k, u)
	_, done2, _ := liveFor(t, g, k, u)
	checkLiveIndex(t, g)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	checkLiveIndex(t, g)
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

func (*failWriter) Interrupt()   {}
func (*failWriter) Close() error { return nil }

// The limited wrappers pass errors through unchanged: an empty read with
// an error, data together with an error (the data first, then the error),
// a cancelled wait (buffered data released), and a failing inner write.
func TestLimitedWrappersErrors(t *testing.T) {
	lim := newUserLimit(1 << 30)
	ctx := context.Background()
	r := &limitedReader{Reader: &errReader{err: io.ErrUnexpectedEOF}, ctx: ctx, b: &lim.up}
	if mb, err := r.ReadMultiBuffer(); !mb.IsEmpty() || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("empty read: %v %v", mb, err)
	}
	inner := &errReader{mb: buf.MergeBytes(nil, []byte("tail")), err: io.EOF}
	r = &limitedReader{Reader: inner, ctx: ctx, b: &lim.up}
	mb, err := r.ReadMultiBuffer()
	if mb.String() != "tail" || !errors.Is(err, io.EOF) {
		t.Fatalf("data+error: %q %v", mb.String(), err)
	}
	buf.ReleaseMulti(mb)
	r.Interrupt()
	if !errors.Is(inner.err, io.ErrClosedPipe) || r.Close() != nil {
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
	if err := w.WriteMultiBuffer(buf.MergeBytes(nil, make([]byte, 3*limitChunk))); !errors.Is(err, io.ErrShortWrite) || fw.calls != 1 {
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
	checkLiveIndex(t, g)
	if c, u := g.LiveStats(); c != 3 || u != 2 {
		t.Fatalf("stats %d conns %d users, want 3 / 2 (u counted once)", c, u)
	}
	// A limit appears on one op: both of the account's dispatches close
	// (they were admitted unthrottled), the other account's do not.
	if n := g.SetLimit("u#1", 1000); n != 2 {
		t.Fatalf("closed %d, want 2", n)
	}
	checkLiveIndex(t, g)
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
	checkLiveIndex(t, g)
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

// UDP inbounds (proxyman worker.go:352) record no Conn: the gate has no
// connection to close for them and must cope.
func TestGateKillWithoutAClientConnection(t *testing.T) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "ss"})
	if clientConn(ctx) != nil {
		t.Fatal("a UDP inbound has no Conn")
	}
	g := newBareGate()
	key := gateKey{tag: "ss", email: "a"}
	u := &protocol.MemoryUser{Email: "a"}
	g.Allow(key, u)
	_, done, _ := liveFor(t, g, key, u)
	g.Revoke(key)
	if !cancelled(done) {
		t.Fatal("dispatch not cancelled")
	}
}

// The account index under concurrent admit/release, revocation, rotation
// and new limits (-race): it always equals live grouped by account, and a
// new limit kills exactly the account's live dispatches, on every one of
// its entrances, and nobody else's.
func TestGateLiveIndexStress(t *testing.T) {
	const accounts, entrances = 16, 3
	g := newBareGate()
	type id struct {
		key  gateKey
		user *protocol.MemoryUser
	}
	var ids []id
	for a := 0; a < accounts; a++ {
		for e := 0; e < entrances; e++ {
			email := fmt.Sprintf("u%d", a)
			if e > 0 {
				email = fmt.Sprintf("u%d#%d", a, e)
			}
			key := gateKey{tag: fmt.Sprintf("in%d", e), email: email}
			u := &protocol.MemoryUser{Email: email}
			g.Allow(key, u)
			ids = append(ids, id{key, u})
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	var wg sync.WaitGroup
	// Relays: admit with whatever identity is current, hold briefly,
	// release (as Dispatch does when the relay ends, killed or not).
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for ctx.Err() == nil {
				x := ids[r.Intn(len(ids))]
				g.mu.Lock()
				u := g.allowed[x.key]
				g.mu.Unlock()
				c := &liveConn{cancel: func() {}}
				if _, ok := g.admit(x.key, u, c); ok {
					time.Sleep(time.Duration(r.Intn(50)) * time.Microsecond)
					g.release(x.key, c)
				}
			}
		}(int64(w))
	}
	// Revocations and rotations of single keys. They pause (killers) while
	// a SetLimit round checks whose dispatches it closed.
	var killers sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := rand.New(rand.NewSource(100))
		for ctx.Err() == nil {
			x := ids[r.Intn(len(ids))]
			killers.Lock()
			if r.Intn(2) == 0 {
				g.Revoke(x.key)
			}
			g.Allow(x.key, &protocol.MemoryUser{Email: x.key.email})
			killers.Unlock()
		}
	}()
	// New limits: each must close exactly the dispatches its account had
	// live at that moment. Probes are admitted on every entrance of the
	// account and of another one just before (with revocations paused);
	// the account's must all be cancelled, the other's must survive.
	r := rand.New(rand.NewSource(200))
	rounds := 0
	for ctx.Err() == nil {
		a, b := r.Intn(accounts), r.Intn(accounts)
		if a == b {
			continue
		}
		var releases []func()
		probe := func(acc int) []<-chan struct{} {
			var done []<-chan struct{}
			for _, x := range ids[acc*entrances : (acc+1)*entrances] {
				pctx, cancel := context.WithCancel(context.Background())
				c := &liveConn{cancel: cancel}
				g.mu.Lock()
				u := g.allowed[x.key]
				g.mu.Unlock()
				if _, ok := g.admit(x.key, u, c); ok {
					done = append(done, pctx.Done())
					releases = append(releases, func() { g.release(x.key, c) })
				}
			}
			return done
		}
		killers.Lock()
		mine, theirs := probe(a), probe(b)
		acc := fmt.Sprintf("u%d", a)
		if n := g.SetLimit(acc, 1<<20); n < len(mine) {
			t.Fatalf("SetLimit(%q) closed %d, but %d probes were live", acc, n, len(mine))
		}
		for _, d := range mine {
			select {
			case <-d:
			default:
				t.Fatalf("SetLimit(%q) left a live dispatch of the account running", acc)
			}
		}
		for _, d := range theirs {
			select {
			case <-d:
				t.Fatalf("SetLimit(%q) closed another account's dispatch", acc)
			default:
			}
		}
		killers.Unlock()
		for _, rel := range releases {
			rel()
		}
		g.SetLimit(acc, 0)
		checkLiveIndex(t, g)
		rounds++
	}
	wg.Wait()
	checkLiveIndex(t, g)
	if rounds == 0 {
		t.Fatal("no SetLimit round ran")
	}
}
