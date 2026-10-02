package main

import (
	"context"
	"errors"
	"sync"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"akari/agent/pb"
)

// errRevoked is returned for dispatches of a user whose access was revoked
// (or replaced) on that inbound.
var errRevoked = errors.New("akari: user access revoked")

// gateKey names one user on one inbound (xray email == panel user id).
type gateKey struct{ tag, email string }

// liveConn is one admitted dispatch: cancelling its context stops the
// outbound side; interrupting its link stops the inbound side.
type liveConn struct {
	cancel context.CancelFunc
	link   *transport.Link
}

// gateDispatcher replaces xray's routing.Dispatcher feature (it wraps a
// DefaultDispatcher). Removing a user from a protocol inbound's validator
// only stops NEW handshakes: already-authenticated connections — and new
// mux sub-streams on them — would keep running. The gate closes that hole:
//
//   - every dispatch carrying a user must present the exact *MemoryUser
//     currently installed for (inbound tag, email) — a removed user, or the
//     old credential of a rotated one, is refused, including new sub-streams
//     of an existing mux connection (they share the outer connection's
//     session user pointer);
//   - admitted dispatches are tracked, and revoking (or replacing) a key
//     cancels and interrupts all of them, which closes the client
//     connection.
//
// Dispatches without a user (none of the panel-managed inbounds produce
// them) pass through untouched.
type gateDispatcher struct {
	inner *dispatcher.DefaultDispatcher

	mu      sync.Mutex
	allowed map[gateKey]*protocol.MemoryUser
	live    map[gateKey]map[*liveConn]struct{}
	// limits: per-user rate limits by email (ratelimit.go); absent = none.
	limits map[string]*userLimit
}

func init() {
	// xray builds apps from typed configs: GateDispatcherConfig in the app
	// list (in place of dispatcher.Config, see newInstance) makes the gate
	// THE dispatcher every inbound resolves at creation.
	common.Must(common.RegisterConfig((*pb.GateDispatcherConfig)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		g := &gateDispatcher{
			inner:   new(dispatcher.DefaultDispatcher),
			allowed: make(map[gateKey]*protocol.MemoryUser),
			live:    make(map[gateKey]map[*liveConn]struct{}),
			limits:  make(map[string]*userLimit),
		}
		err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
			return g.inner.Init(&dispatcher.Config{}, om, router, pm, sm)
		})
		if err != nil {
			return nil, err
		}
		return g, nil
	}))
}

// Type implements common.HasType: this IS the instance's dispatcher.
func (*gateDispatcher) Type() interface{} { return routing.DispatcherType() }

func (*gateDispatcher) Start() error { return nil }

func (g *gateDispatcher) Close() error {
	g.mu.Lock()
	var all []*liveConn
	for k, conns := range g.live {
		for c := range conns {
			all = append(all, c)
		}
		delete(g.live, k)
	}
	g.allowed = make(map[gateKey]*protocol.MemoryUser)
	g.mu.Unlock()
	for _, c := range all {
		c.kill()
	}
	return nil
}

func (c *liveConn) kill() {
	c.cancel()
	if c.link != nil {
		_ = common.Interrupt(c.link.Reader)
		_ = common.Interrupt(c.link.Writer)
	}
}

// Allow installs user as the only admissible identity for key. A different
// previous user for the key (rotated credential) loses its live links.
func (g *gateDispatcher) Allow(key gateKey, user *protocol.MemoryUser) {
	g.mu.Lock()
	prev, had := g.allowed[key]
	g.allowed[key] = user
	var victims []*liveConn
	if had && prev != user {
		victims = g.takeLocked(key)
	}
	g.mu.Unlock()
	for _, c := range victims {
		c.kill()
	}
}

// Revoke refuses key from now on and closes its live links. Returns how
// many were closed.
func (g *gateDispatcher) Revoke(key gateKey) int {
	g.mu.Lock()
	delete(g.allowed, key)
	victims := g.takeLocked(key)
	g.mu.Unlock()
	for _, c := range victims {
		c.kill()
	}
	return len(victims)
}

func (g *gateDispatcher) takeLocked(key gateKey) []*liveConn {
	conns := g.live[key]
	delete(g.live, key)
	out := make([]*liveConn, 0, len(conns))
	for c := range conns {
		out = append(out, c)
	}
	return out
}

// LiveTotal returns the number of tracked dispatches over all keys.
func (g *gateDispatcher) LiveTotal() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, conns := range g.live {
		n += len(conns)
	}
	return n
}

// Live returns the number of tracked dispatches for key (tests).
func (g *gateDispatcher) Live(key gateKey) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.live[key])
}

func identity(ctx context.Context) (gateKey, *protocol.MemoryUser, bool) {
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil {
		return gateKey{}, nil, false
	}
	return gateKey{tag: in.Tag, email: in.User.Email}, in.User, true
}

// admit registers c under key iff user is the key's current identity, and
// returns the user's rate limit (nil = unlimited).
func (g *gateDispatcher) admit(key gateKey, user *protocol.MemoryUser, c *liveConn) (*userLimit, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cur, ok := g.allowed[key]; !ok || cur != user {
		return nil, false
	}
	conns := g.live[key]
	if conns == nil {
		conns = make(map[*liveConn]struct{})
		g.live[key] = conns
	}
	conns[c] = struct{}{}
	return g.limits[key.email], true
}

func (g *gateDispatcher) release(key gateKey, c *liveConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if conns := g.live[key]; conns != nil {
		delete(conns, c)
		if len(conns) == 0 {
			delete(g.live, key)
		}
	}
}

// Dispatch implements routing.Dispatcher. Unlike DefaultDispatcher.Dispatch
// (which fires the outbound relay in a goroutine nobody can observe), the
// relay runs here as DispatchLink over our own pipes, so the tracked entry
// lives exactly as long as the relay — mux sub-streams on a long-lived
// connection do not pile up.
func (g *gateDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	key, user, managed := identity(ctx)
	if !managed {
		return g.inner.Dispatch(ctx, dest)
	}
	if !dest.IsValid() {
		return nil, errors.New("dispatcher: invalid destination")
	}
	ctx, cancel := context.WithCancel(ctx)
	opt := pipe.OptionsFromContext(ctx)
	upR, upW := pipe.New(opt...)
	downR, downW := pipe.New(opt...)
	in := &transport.Link{Reader: downR, Writer: upW}
	out := &transport.Link{Reader: upR, Writer: downW}
	c := &liveConn{cancel: cancel, link: in}
	lim, ok := g.admit(key, user, c)
	if !ok {
		cancel()
		return nil, errRevoked
	}
	limited := limitLink(ctx, out, lim)
	go func() {
		defer g.release(key, c)
		defer cancel()
		if err := g.inner.DispatchLink(ctx, dest, limited); err != nil {
			_ = common.Interrupt(upR)
			_ = common.Interrupt(downW)
		}
	}()
	return in, nil
}

// DispatchLink implements routing.Dispatcher. It runs the whole relay
// synchronously, so revocation cancels its context.
func (g *gateDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	key, user, managed := identity(ctx)
	if !managed {
		return g.inner.DispatchLink(ctx, dest, link)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &liveConn{cancel: cancel, link: link}
	lim, ok := g.admit(key, user, c)
	if !ok {
		return errRevoked
	}
	defer g.release(key, c)
	return g.inner.DispatchLink(ctx, dest, limitLink(ctx, link, lim))
}
