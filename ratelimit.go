package main

import (
	"context"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// Per-user speed limits (protocol 4, UserOp.speed_limit_bytes_per_sec).
//
// xray-core has no per-user rate limiting, so the gate does it: every
// dispatch of a limited user gets its link wrapped in pacing readers/writers
// that draw from ONE pair of buckets per user (uplink, downlink), shared by
// all of that user's connections and inbounds on this node. Unlimited users
// are never wrapped: the only cost on their path is one map lookup in admit,
// under the lock admit already takes.
//
// XTLS Vision's splice copies bytes kernel-to-kernel and bypasses every
// reader/writer, so every managed dispatch turns splice off (limitLink;
// session.Inbound.CanSpliceCopy = 3, the value xray itself uses for "never
// splice"); Vision keeps working, just through user space.
//
// Only the OUTBOUND side of a dispatch is wrapped: its reader (uplink) and
// writer (downlink). The inbound side (the link Dispatch returns, which
// xray's mux server keeps and asserts to be a *pipe.Reader for XUDP) is
// never wrapped; on the DispatchLink path the outbound-side reader is
// wrapped by xray's own WrapLink in a TimeoutWrapperReader anyway. Pacing
// never errors on large batches: reservations are in virtual time (no
// "n > burst" failure) and each pass is at most limitChunk.
//
// A limit that appears where there was none closes the user's live
// dispatches (see gateDispatcher.SetLimit): unwrapped connections (possibly
// spliced) could not be throttled. Changing or removing an existing limit
// applies to live connections in place (the buckets are shared and read
// the rate atomically).

// limitBurstMin is the smallest burst a bucket allows (bytes): about one
// TLS record batch, so small exchanges are not delayed at all.
const limitBurstMin = 64 << 10

// limitChunk is the most a wrapper passes per reservation. Pipes can hand
// over hundreds of KiB at once; pacing that as one block would hold the
// whole batch for seconds and then release it in one go (stalling the
// other direction of request/response protocols). Chunks keep both
// directions flowing at the rate.
const limitChunk = 32 << 10

// monoStart anchors the monotonic clock buckets run on.
var monoStart = time.Now()

func monoNanos() int64 { return int64(time.Since(monoStart)) }

// bucket paces bytes to rate (bytes/s) with a burst of max(rate/5,
// limitBurstMin) bytes. It is a virtual-time (GCRA-like) scheduler: each
// reservation of n bytes advances tat by n/rate and waits until tat is
// within the burst window of now. Long-run throughput is at most
// rate*T + burst; callers are served in reservation order.
type bucket struct {
	rate atomic.Uint64 // bytes per second; 0 = unlimited
	mu   sync.Mutex
	tat  int64 // theoretical arrival time, monoNanos
	used bool  // tat is set (a fresh bucket starts with one full burst)
}

// costNanos is n bytes at rate r, in nanoseconds (saturating).
func costNanos(n, r uint64) int64 {
	hi, lo := bits.Mul64(n, uint64(time.Second))
	if hi >= r {
		return int64(^uint64(0) >> 1)
	}
	q, _ := bits.Div64(hi, lo, r)
	if q > uint64(^uint64(0)>>1) {
		return int64(^uint64(0) >> 1)
	}
	return int64(q)
}

func burstNanos(r uint64) int64 {
	b := r / 5
	if b < limitBurstMin {
		b = limitBurstMin
	}
	return costNanos(b, r)
}

// reserve books n bytes at time now and returns how long the caller must
// wait before passing them on (0 = immediately).
func (b *bucket) reserve(n int, now int64) time.Duration {
	r := b.rate.Load()
	if r == 0 || n <= 0 {
		return 0
	}
	b.mu.Lock()
	base := b.tat
	if floor := now - burstNanos(r); !b.used || base < floor {
		base = floor
	}
	b.used = true
	c := costNanos(uint64(n), r)
	if base > int64(^uint64(0)>>1)-c {
		b.tat = int64(^uint64(0) >> 1)
	} else {
		b.tat = base + c
	}
	wait := b.tat - now
	b.mu.Unlock()
	if wait <= 0 {
		return 0
	}
	return time.Duration(wait)
}

// wait books n bytes and sleeps until they may pass, or ctx ends.
func (b *bucket) wait(ctx context.Context, n int) error {
	d := b.reserve(n, monoNanos())
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// userLimit is one user's pair of buckets on this node.
type userLimit struct {
	up   bucket // client -> destination (what the outbound reads)
	down bucket // destination -> client (what the outbound writes)
}

func newUserLimit(bps uint64) *userLimit {
	l := &userLimit{}
	l.set(bps)
	return l
}

func (l *userLimit) set(bps uint64) {
	l.up.rate.Store(bps)
	l.down.rate.Store(bps)
}

// limitedReader paces what the outbound reads from the client (uplink): the
// bytes are read, then held back until the bucket allows them through, so
// the client's TCP window fills while we wait.
type limitedReader struct {
	buf.Reader
	ctx context.Context
	b   *bucket
	// Read but not yet passed on (beyond one chunk), and the inner error
	// that came with it (returned once it is drained).
	pending buf.MultiBuffer
	err     error
}

func (r *limitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.pending.IsEmpty() {
		if r.err != nil {
			return nil, r.err
		}
		r.pending, r.err = r.Reader.ReadMultiBuffer()
		if r.pending.IsEmpty() {
			err := r.err
			r.err = nil
			return nil, err
		}
	}
	rest, head := buf.SplitSize(r.pending, limitChunk)
	r.pending = rest
	if werr := r.b.wait(r.ctx, int(head.Len())); werr != nil {
		buf.ReleaseMulti(head)
		buf.ReleaseMulti(r.pending)
		r.pending = nil
		return nil, werr
	}
	if r.pending.IsEmpty() {
		err := r.err
		r.err = nil
		return head, err
	}
	return head, nil
}

func (r *limitedReader) Interrupt()   { _ = common.Interrupt(r.Reader) }
func (r *limitedReader) Close() error { return common.Close(r.Reader) }

// limitedWriter paces what the outbound writes back to the client
// (downlink).
type limitedWriter struct {
	buf.Writer
	ctx context.Context
	b   *bucket
}

func (w *limitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for !mb.IsEmpty() {
		var head buf.MultiBuffer
		mb, head = buf.SplitSize(mb, limitChunk)
		if err := w.b.wait(w.ctx, int(head.Len())); err != nil {
			buf.ReleaseMulti(head)
			buf.ReleaseMulti(mb)
			return err
		}
		if err := w.Writer.WriteMultiBuffer(head); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func (w *limitedWriter) Interrupt()   { _ = common.Interrupt(w.Writer) }
func (w *limitedWriter) Close() error { return common.Close(w.Writer) }

// limitLink returns the outbound-side link of a limited user's dispatch
// (nil lim = the link itself) and turns splice off for the connection.
//
// Splice is off for every managed user, limited or not: xray's splice copy
// (proxy.CopyRawConnIfExist, v26.3.27) is one blocking ReadFrom that adds
// the bytes to the user's downlink counter only when the connection ends.
// A long Vision download was therefore invisible to reports and quota
// enforcement while it ran, and lost entirely when the instance was torn
// down first (Snapshot rebuild, graceful stop, self-update, lease expiry,
// a crash): the counters were read before Close ended the connection
// (test bed 2026-10-10: 0 of 225 MB billed). Without splice the bytes go
// through the counted link writer as they flow; the XTLS framing is
// unchanged, the copy costs ~12% single-stream throughput on loopback.
func limitLink(ctx context.Context, link *transport.Link, lim *userLimit) *transport.Link {
	if in := session.InboundFromContext(ctx); in != nil && in.CanSpliceCopy != 3 {
		in.CanSpliceCopy = 3
	}
	if lim == nil {
		return link
	}
	return &transport.Link{
		Reader: &limitedReader{Reader: link.Reader, ctx: ctx, b: &lim.up},
		Writer: &limitedWriter{Writer: link.Writer, ctx: ctx, b: &lim.down},
	}
}

// SetLimit installs the rate (bytes/s per direction; 0 = none) an op of
// email carries. The limit is the account's (protocol 7, accountOf): all
// of the account's emails (entrances) share one pair of buckets, and it
// stays while any of them still carries it. A limit where there was none
// closes the account's live dispatches on every inbound (they were
// admitted unwrapped, possibly spliced, and could not be throttled);
// clients reconnect under the limit. Returns how many closed.
func (g *gateDispatcher) SetLimit(email string, bps uint64) int {
	acc := accountOf(email)
	g.mu.Lock()
	cur := g.limits[acc]
	var victims []*liveConn
	switch {
	case bps == 0:
		if set := g.limited[acc]; set != nil {
			delete(set, email)
			if len(set) == 0 {
				delete(g.limited, acc)
				// Live wrapped connections become unthrottled in place.
				cur.set(0)
				delete(g.limits, acc)
			}
		}
	case cur != nil:
		g.limited[acc][email] = struct{}{}
		cur.set(bps)
	default:
		g.limits[acc] = newUserLimit(bps)
		g.limited[acc] = map[string]struct{}{email: {}}
		for key := range g.live {
			if accountOf(key.email) == acc {
				victims = append(victims, g.takeLocked(key)...)
			}
		}
	}
	g.mu.Unlock()
	for _, c := range victims {
		c.kill()
	}
	return len(victims)
}

// Limit returns the installed rate of email's account (0 = none).
func (g *gateDispatcher) Limit(email string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if l := g.limits[accountOf(email)]; l != nil {
		return l.up.rate.Load()
	}
	return 0
}
