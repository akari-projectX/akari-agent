//go:build soak

// The soak test's load driver (soak_test.go): what the fake panel does over
// time, the revocation checks and the end-of-run assertions.

package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"akari/agent/pb"
)

var soakLimits = []uint64{0, 1 << 20, 4 << 20}

func (h *soak) newGhost(id string) *sUser {
	u := &sUser{key: id, relay: strings.HasSuffix(id, "#1"), tags: map[string]int{}}
	h.ghostGen[id]++
	h.ghostTags(u)
	return u
}

func (h *soak) ghostTags(u *sUser) {
	gen := h.ghostGen[u.key]
	if u.relay {
		u.tags["e1"] = gen
		return
	}
	tags := directTags()
	h.rng2.Shuffle(len(tags), func(i, j int) { tags[i], tags[j] = tags[j], tags[i] })
	for _, t := range tags[:1+h.rng2.IntN(len(tags))] {
		u.tags[t] = gen
	}
}

// ghostChurn: k random operations on the ghost pool.
func (h *soak) ghostChurn(k int) []*pb.UserOp {
	var ops []*pb.UserOp
	for range k {
		var id string
		if h.rng2.IntN(5) == 0 {
			id = h.ghostRel[h.rng2.IntN(len(h.ghostRel))]
		} else {
			id = h.ghostIDs[h.rng2.IntN(len(h.ghostIDs))]
		}
		u := h.users[id]
		if u == nil { // add; the same credential again or a new one
			if h.rng2.IntN(2) == 0 {
				h.ghostGen[id]++
			}
			nu := &sUser{key: id, relay: strings.HasSuffix(id, "#1"), tags: map[string]int{}}
			h.ghostTags(nu)
			if h.rng2.IntN(10) == 0 {
				nu.limit = soakLimits[1+h.rng2.IntN(2)]
			}
			h.setUser(nu)
			ops = append(ops, nu.addOp())
			continue
		}
		switch r := h.rng2.IntN(100); {
		case r < 40: // remove
			h.delUser(id)
			ops = append(ops, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: id})
		case r < 70: // rotate some credentials
			for _, t := range u.tagNames() {
				if h.rng2.IntN(2) == 0 || len(u.tags) == 1 {
					h.ghostGen[id]++
					u.tags[t] = h.ghostGen[id]
				}
			}
			ops = append(ops, u.addOp())
		case r < 85: // change the inbound set
			if !u.relay {
				if len(u.tags) > 1 && h.rng2.IntN(2) == 0 {
					delete(u.tags, u.tagNames()[h.rng2.IntN(len(u.tags))])
				} else {
					for _, t := range directTags() {
						if _, has := u.tags[t]; !has {
							u.tags[t] = h.ghostGen[id]
							break
						}
					}
				}
				h.setUser(u)
			}
			ops = append(ops, u.addOp())
		default: // speed limit
			u.limit = soakLimits[h.rng2.IntN(len(soakLimits))]
			ops = append(ops, u.addOp())
		}
	}
	h.ev.ghostOps.Add(int64(len(ops)))
	return ops
}

// freshChurn: brand-new ids (never seen before) that live for 20-60s, the
// way short-lived accounts churn on a busy node.
func (h *soak) freshChurn(n int) []*pb.UserOp {
	var ops []*pb.UserOp
	now := time.Now()
	for range n {
		h.freshSeq++
		u := &sUser{key: fmt.Sprintf("f%07d", h.freshSeq), tags: map[string]int{}}
		for _, t := range directTags() {
			u.tags[t] = 0
		}
		h.setUser(u)
		ops = append(ops, u.addOp())
		h.fresh = append(h.fresh, freshUser{key: u.key, due: now.Add(time.Duration(20+h.rng2.IntN(40)) * time.Second)})
		h.ev.freshAdded.Add(1)
	}
	keep := h.fresh[:0]
	for _, f := range h.fresh {
		if now.After(f.due) {
			h.delUser(f.key)
			ops = append(ops, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: f.key})
			h.ev.freshRemoved.Add(1)
		} else {
			keep = append(keep, f)
		}
	}
	h.fresh = keep
	return ops
}

// lchange is one transition of a live user.
type lchange struct {
	kind    string
	ops     []*pb.UserOp
	revoked []string // slots whose credential vanished (must be cut and refused)
	keep    []string // slots that must stay connected
	after   func()   // brings the clients in line (set/resume)
}

func (l *liveUser) presentTags() []string {
	var out []string
	for _, k := range soakKinds {
		if _, ok := l.entity(k.tag).tags[k.tag]; ok && l.present {
			out = append(out, k.tag)
		}
	}
	return out
}

func (l *liveUser) missingTags() []string {
	var out []string
	for _, k := range soakKinds {
		if _, ok := l.entity(k.tag).tags[k.tag]; !ok {
			out = append(out, k.tag)
		}
	}
	return out
}

func (l *liveUser) slot(tag string) string { return slotName(l.entity(tag).key, tag) }

func (h *soak) planLive(l *liveUser) *lchange {
	if !l.present {
		return h.planReadd(l)
	}
	present := l.presentTags()
	missing := l.missingTags()
	r := h.rng.IntN(100)
	switch {
	case len(missing) > 0 && r < 40:
		return h.planRestore(l, missing)
	case r < 25:
		return h.planRemove(l, present)
	case r < 60:
		return h.planRotate(l, present)
	case r < 75 && len(present) >= 3:
		return h.planDrop(l, present)
	default:
		return h.planLimit(l)
	}
}

func (h *soak) entityOps(l *liveUser) []*pb.UserOp {
	var ops []*pb.UserOp
	for _, e := range []*sUser{l.direct, l.relay} {
		if len(e.tags) == 0 {
			if _, in := h.users[e.key]; in {
				h.delUser(e.key)
				ops = append(ops, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: e.key})
			}
			continue
		}
		h.setUser(e)
		ops = append(ops, e.addOp())
	}
	return ops
}

func (h *soak) planRemove(l *liveUser, present []string) *lchange {
	c := &lchange{kind: "remove"}
	for _, t := range present {
		c.revoked = append(c.revoked, l.slot(t))
	}
	for _, e := range []*sUser{l.direct, l.relay} {
		h.delUser(e.key)
		c.ops = append(c.ops, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: e.key})
		e.tags = map[string]int{}
	}
	l.present = false
	return c
}

func (h *soak) planRotate(l *liveUser, present []string) *lchange {
	c := &lchange{kind: "rotate"}
	h.rng.Shuffle(len(present), func(i, j int) { present[i], present[j] = present[j], present[i] })
	n := min(1+h.rng.IntN(3), len(present))
	rot := present[:n]
	for _, t := range present {
		if slices.Contains(rot, t) {
			c.revoked = append(c.revoked, l.slot(t))
		} else {
			c.keep = append(c.keep, l.slot(t))
		}
	}
	for _, t := range rot {
		l.entity(t).tags[t]++
	}
	c.ops = h.entityOps(l)
	c.after = func() {
		for _, t := range rot {
			g := l.entity(t).tags[t]
			h.setSlot(l.entity(t).key, t, g)
			l.childGen[t] = g
		}
	}
	h.ev.rotations.Add(1)
	return c
}

func (h *soak) planDrop(l *liveUser, present []string) *lchange {
	c := &lchange{kind: "drop"}
	h.rng.Shuffle(len(present), func(i, j int) { present[i], present[j] = present[j], present[i] })
	drop := present[:1+h.rng.IntN(2)]
	for _, t := range present {
		if slices.Contains(drop, t) {
			c.revoked = append(c.revoked, l.slot(t))
		} else {
			c.keep = append(c.keep, l.slot(t))
		}
	}
	for _, t := range drop {
		delete(l.entity(t).tags, t)
	}
	c.ops = h.entityOps(l)
	return c
}

func (h *soak) planRestore(l *liveUser, missing []string) *lchange {
	c := &lchange{kind: "restore"}
	for _, t := range l.presentTags() {
		c.keep = append(c.keep, l.slot(t))
	}
	var back []string
	for _, t := range missing {
		g := l.childGen[t]
		if h.rng.IntN(2) == 0 {
			g++
		}
		l.entity(t).tags[t] = g
		back = append(back, t)
	}
	c.ops = h.entityOps(l)
	c.after = func() { h.bringUp(l, back) }
	h.ev.restores.Add(1)
	return c
}

func (h *soak) planReadd(l *liveUser) *lchange {
	c := &lchange{kind: "readd"}
	var all []string
	for _, k := range soakKinds {
		g := l.childGen[k.tag]
		if h.rng.IntN(2) == 0 {
			g++
		}
		l.entity(k.tag).tags[k.tag] = g
		all = append(all, k.tag)
	}
	l.direct.limit = soakLimits[h.rng.IntN(len(soakLimits))]
	l.relay.limit = l.direct.limit
	l.present = true
	c.ops = h.entityOps(l)
	c.after = func() { h.bringUp(l, all) }
	return c
}

// bringUp starts (new credential) or resumes (same credential, the client
// keeps its instance and possibly its QUIC session) the clients of tags.
func (h *soak) bringUp(l *liveUser, tags []string) {
	var resume []string
	for _, t := range tags {
		e := l.entity(t)
		if g := e.tags[t]; g != l.childGen[t] {
			h.setSlot(e.key, t, g)
			l.childGen[t] = g
		} else {
			resume = append(resume, slotName(e.key, t))
		}
	}
	if len(resume) > 0 {
		if _, err := h.call(soakReq{Op: "resume", Slots: resume}); err != nil {
			h.violate("child resume: %v", err)
		}
	}
}

func (h *soak) planLimit(l *liveUser) *lchange {
	c := &lchange{kind: "limit"}
	nl := soakLimits[h.rng.IntN(len(soakLimits))]
	l.direct.limit, l.relay.limit = nl, nl
	c.ops = h.entityOps(l)
	h.ev.limits.Add(1)
	return c
}

// liveStep performs one due transition of a live user (if any) and checks
// the revocation guarantees.
// stalledTolerance: bytes the agent may still count for a revoked user after
// the delta's acknowledgement (in flight inside xray's pipes at the cut).
const stalledTolerance = 64 << 10

func (h *soak) liveStep() {
	now := time.Now()
	var l *liveUser
	for _, c := range h.live {
		if now.After(c.next) {
			l = c
			break
		}
	}
	if l == nil {
		return
	}
	l.next = now.Add(time.Duration(15+h.rng.IntN(30)) * time.Second)
	began := time.Now()
	var kind string
	defer func() { h.logf("live %s: %s took %v", l.id, kind, time.Since(began).Round(time.Millisecond)) }()

	// The model change, the pre-check of the connections and the delta are
	// one step as far as the other goroutine's deltas are concerned.
	h.txMu.Lock()
	c := h.planLive(l)
	kind = c.kind
	var liveRev, liveKeep []string
	if len(c.revoked)+len(c.keep) > 0 {
		r, err := h.call(soakReq{Op: "prep", Slots: append(slices.Clone(c.revoked), c.keep...)})
		if err != nil {
			h.violate("child prep: %v", err)
		} else {
			for _, s := range r.Live {
				if slices.Contains(c.revoked, s) {
					liveRev = append(liveRev, s)
				} else {
					liveKeep = append(liveKeep, s)
				}
			}
		}
	}
	t1 := time.Now()
	sent := h.sendDeltaLocked(c.ops)
	h.txMu.Unlock()
	t2 := time.Now()
	if !sent {
		// The stream went away: the resync Snapshot carries the change.
		h.logf("live %s %s: stream lost during the delta; waiting for the resync", l.id, c.kind)
		h.waitReady(90 * time.Second)
	}
	h.ev.batches.Add(1)
	if len(c.revoked) > 0 {
		h.ev.revokes.Add(int64(len(c.revoked)))
		h.ev.revokedLive.Add(int64(len(liveRev)))
		before := map[string]uint64{}
		for _, s := range liveRev {
			before[s] = h.relayedBytes(s)
		}
		r, err := h.call(soakReq{Op: "expect_cut", Slots: c.revoked})
		if err != nil {
			h.violate("child expect_cut: %v", err)
		} else {
			for _, s := range liveRev {
				if !slices.Contains(r.NotCut, s) {
					h.ev.cutOK.Add(1)
					h.recordCut(s, r.CutMs[s])
					continue
				}
				// The client's connection was still open after 6s. What
				// matters for revocation is whether anything crossed: an
				// echo completing after the delta, bytes counted for the
				// user, or a dispatch the gate still tracks. A connection
				// that is merely open (the agent closed its side; the
				// client's xray did not follow) relays nothing.
				uid, tag, _ := strings.Cut(s, "|")
				counted, tracked := h.relayedBytes(s)-before[s], h.liveDispatches(tag, uid)
				if r.Echoed[s] > 0 || counted > stalledTolerance || tracked > 0 {
					h.violate("%s %s: revoked connection %s kept relaying (echoes after the revocation=%d, %d bytes counted for the user since the delta's ack, %d dispatches still tracked; client: %s)",
						l.id, c.kind, s, r.Echoed[s], counted, tracked, r.Detail[s])
				} else {
					h.ev.stalled.Add(1)
					h.logf("%s %s: %s not closed by its client within 6s, but nothing crossed after the revocation (0 dispatches tracked, %d bytes counted; client: %s)",
						l.id, c.kind, s, counted, r.Detail[s])
				}
			}
			for _, s := range r.Allowed {
				h.violate("%s %s: revoked credential %s opened a new connection", l.id, c.kind, s)
			}
			h.ev.newRefused.Add(int64(len(c.revoked) - len(r.Allowed)))
			h.ev.unverified.Add(int64(len(c.revoked) - len(liveRev)))
		}
	}
	if len(liveKeep) > 0 {
		time.Sleep(time.Second)
		r, err := h.call(soakReq{Op: "alive", Slots: liveKeep})
		if err == nil {
			h.ev.collateralChecked.Add(int64(len(liveKeep)))
			for _, s := range liveKeep {
				if !slices.Contains(r.Alive, s) {
					h.ev.collateralCut.Add(1)
					h.logf("collateral: %s lost its connection during %s of %s", s, c.kind, l.id)
				}
			}
		}
	}
	t3 := time.Now()
	if c.after != nil {
		c.after()
	}
	if d := time.Since(began); d > 5*time.Second {
		h.logf("live %s %s slow: plan+prep %v, delta %v, verify %v, after %v", l.id, c.kind, t1.Sub(began), t2.Sub(t1), t3.Sub(t2), time.Since(t3))
	}
}

// ghostLoop: the churn of the ghost pool and of fresh ids, a delta every
// 1-3s, until stop is closed.
// relayedBytes is what the agent's xray has counted for the slot's user so
// far (up + down): its growth after a revocation is data that crossed.
func (h *soak) relayedBytes(slot string) uint64 {
	uid, _, _ := strings.Cut(slot, "|")
	var n uint64
	m := h.a.core
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.counted[uid]; c != nil {
		n = uint64(c.up.Value()) + uint64(c.down.Value())
	}
	return n
}

// liveDispatches is the number of dispatches the gate still tracks for the
// key.
func (h *soak) liveDispatches(tag, uid string) int {
	if g := h.a.core.liveGate.Load(); g != nil {
		return g.Live(gateKey{tag: tag, email: uid})
	}
	return -1
}

// recordCut keeps the time a revoked live connection took to close.
func (h *soak) recordCut(slot string, ms int64) {
	h.vmu.Lock()
	h.cutLat = append(h.cutLat, cutSample{slot: slot, ms: ms})
	h.vmu.Unlock()
}

type cutSample struct {
	slot string
	ms   int64
}

// cutLatency describes how long revoked live connections took to close, per
// protocol (the harness gives a connection 6s).
func (h *soak) cutLatency() string {
	h.vmu.Lock()
	cuts := slices.Clone(h.cutLat)
	h.vmu.Unlock()
	by := map[string][]int64{}
	for _, c := range cuts {
		_, tag, _ := strings.Cut(c.slot, "|")
		by[tag] = append(by[tag], c.ms)
	}
	var tags []string
	for t := range by {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	var parts []string
	for _, t := range tags {
		v := by[t]
		slices.Sort(v)
		parts = append(parts, fmt.Sprintf("%s n=%d p50=%dms p99=%dms max=%dms", t, len(v), v[len(v)/2], v[len(v)*99/100], v[len(v)-1]))
	}
	return "cut latency: " + strings.Join(parts, "; ")
}

func (h *soak) ghostLoop(stop <-chan struct{}) {
	churn, fresh := envInt("SOAK_GHOST_OPS", 40), envInt("SOAK_FRESH", 10)
	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(1000+h.rng2.IntN(2000)) * time.Millisecond):
		}
		if !h.waitReady(60 * time.Second) {
			continue
		}
		h.txMu.Lock()
		ops := append(h.ghostChurn(churn), h.freshChurn(fresh)...)
		sent := h.sendDeltaLocked(ops)
		h.txMu.Unlock()
		if sent {
			h.ev.ghostBatches.Add(1)
		}
	}
}

func (h *soak) driveLoad(end time.Time) {
	stopGhosts := make(chan struct{})
	ghostsDone := make(chan struct{})
	go func() { defer close(ghostsDone); h.ghostLoop(stopGhosts) }()
	defer func() { close(stopGhosts); <-ghostsDone }()
	now := time.Now()
	lastSnap, lastKill, lastLease := now, now.Add(-h.cfg.killEvery/2), now
	for time.Now().Before(end) {
		if !h.waitReady(60 * time.Second) {
			h.violate("the agent did not reconnect within 60s")
			time.Sleep(5 * time.Second)
			continue
		}
		now = time.Now()
		switch {
		case now.Sub(lastSnap) >= h.cfg.snapEvery:
			h.logf("driver: snapshot (xray rebuild)")
			h.sendSnapshot()
			lastSnap = now
			time.Sleep(4 * time.Second)
		case now.Sub(lastKill) >= h.cfg.killEvery:
			h.logf("driver: killing the stream")
			h.killStream()
			lastKill = now
			time.Sleep(4 * time.Second)
		default:
			h.liveStep()
		}
		if now.Sub(lastLease) >= 30*time.Second {
			h.sendLease()
			lastLease = now
		}
		time.Sleep(time.Duration(500+h.rng.IntN(1000)) * time.Millisecond)
	}
}

// ---------------------------------------------------------------- accounting

func (h *soak) checkAccounting() {
	r, err := h.call(soakReq{Op: "stats"})
	if err != nil || r.Stats == nil {
		h.violate("child stats: %v", err)
		return
	}
	type tot struct{ w, r, rPlain int64 }
	clients := map[string]*tot{}
	for _, s := range r.Stats.Slots {
		t := clients[s.User]
		if t == nil {
			t = &tot{}
			clients[s.User] = t
		}
		t.w += s.Written
		t.r += s.Read
		if !s.TLS {
			t.rPlain += s.Read
		}
	}
	h.acctMu.Lock()
	billed := map[string][2]uint64{}
	for k, v := range h.acct {
		b := billed[k[1]]
		billed[k[1]] = [2]uint64{b[0] + v[0], b[1] + v[1]}
	}
	h.acctMu.Unlock()
	users := make([]string, 0, len(clients))
	for u := range clients {
		users = append(users, u)
	}
	sort.Strings(users)
	const tol = 0.03
	h.logf("accounting (client raw bytes vs panel-side accounted bytes, max per session summed):")
	var sw, sr, su, sd int64
	for _, u := range users {
		c, b := clients[u], billed[u]
		up, down := int64(b[0]), int64(b[1])
		sw, sr, su, sd = sw+c.w, sr+c.r, su+up, sd+down
		lossUp := float64(c.w-up) / math.Max(1, float64(c.w))
		diffDown := float64(down-c.r) / math.Max(1, float64(c.r))
		h.logf("  %-10s wrote=%12d accUp=%12d (%.3f%% unaccounted)  read=%12d accDown=%12d (%+.3f%%)",
			u, c.w, up, 100*lossUp, c.r, down, 100*diffDown)
		if up > c.w {
			h.violate("accounting %s: accounted up %d > bytes the clients wrote %d", u, up, c.w)
		}
		if down < c.r {
			h.violate("accounting %s: accounted down %d < bytes the clients read %d", u, down, c.r)
		}
		if up < c.rPlain {
			h.violate("accounting %s: accounted up %d < %d bytes the clients got echoed back through plain slots", u, up, c.rPlain)
		}
		if lossUp > tol && c.w > 50<<20 {
			h.violate("accounting %s: %.2f%% of the uploaded bytes unaccounted (tolerance %.0f%%)", u, 100*lossUp, 100*tol)
		}
		if diffDown > tol && c.r > 50<<20 {
			h.violate("accounting %s: accounted down exceeds what the clients read by %.2f%% (tolerance %.0f%%)", u, 100*diffDown, 100*tol)
		}
	}
	h.logf("  TOTAL      wrote=%12d accUp=%12d (%.4f%% unaccounted)  read=%12d accDown=%12d (%+.4f%%)", sw, su,
		100*float64(sw-su)/math.Max(1, float64(sw)), sr, sd, 100*float64(sd-sr)/math.Max(1, float64(sr)))
	for u, b := range billed {
		if _, ok := clients[u]; !ok && (b[0] != 0 || b[1] != 0) {
			h.violate("accounting: %d/%d bytes billed to %s, which never had a client", b[0], b[1], u)
		}
	}
}

// ---------------------------------------------------------------- summary

func mib(b uint64) float64 { return float64(b) / (1 << 20) }

func (h *soak) summary(base, idle, drained, end procSample, samples []procSample) {
	var b strings.Builder
	e := &h.ev
	fmt.Fprintf(&b, "streams=%d kills=%d snapshots=%d (fallback %d) deltas=%d resync(in-sync=%d, snapshot=%d) leases=%d ack-not-ok=%d hash-mismatch=%d\n",
		h.streams.Load(), e.kills.Load(), e.snapshots.Load(), e.fallbackSnapshots.Load(), e.deltas.Load(), e.resyncNone.Load(), e.resyncSnapshot.Load(),
		e.leases.Load(), e.ackNotOK.Load(), e.hashMismatch.Load())
	fmt.Fprintf(&b, "ghost batches=%d ops=%d fresh added=%d removed=%d unique users installed=%d\n", e.ghostBatches.Load(), e.ghostOps.Load(), e.freshAdded.Load(), e.freshRemoved.Load(), h.unique.Load())
	fmt.Fprintf(&b, "live transitions: batches=%d rotations=%d restores=%d limit changes=%d\n", e.batches.Load(), e.rotations.Load(), e.restores.Load(), e.limits.Load())
	fmt.Fprintf(&b, "revocation: slots revoked=%d (with a live connection beforehand=%d, proven cut=%d, no live connection to check=%d), new connection refused=%d\n",
		e.revokes.Load(), e.revokedLive.Load(), e.cutOK.Load(), e.unverified.Load(), e.newRefused.Load())
	fmt.Fprintf(&b, "%s; revoked live connections left open by their client for >6s with nothing relayed=%d\n", h.cutLatency(), e.stalled.Load())
	fmt.Fprintf(&b, "collateral: untouched live connections checked=%d lost=%d\n", e.collateralChecked.Load(), e.collateralCut.Load())
	fmt.Fprintf(&b, "traffic reports=%d rows=%d heartbeats=%d\n", e.trafficReports.Load(), e.trafficRows.Load(), e.heartbeats.Load())
	fmt.Fprintf(&b, "baseline: heap_live=%.1fMiB rss=%.1fMiB goroutines=%d fds=%d\n", mib(base.HeapLive), mib(base.RSS), base.Goroutines, base.FDs)
	fmt.Fprintf(&b, "idle:     heap_live=%.1fMiB rss=%.1fMiB goroutines=%d fds=%d\n", mib(idle.HeapLive), mib(idle.RSS), idle.Goroutines, idle.FDs)
	fmt.Fprintf(&b, "drained:  heap_live=%.1fMiB rss=%.1fMiB goroutines=%d fds=%d counted=%d issued=%d\n", mib(drained.HeapLive), mib(drained.RSS), drained.Goroutines, drained.FDs, drained.Counted, drained.Issued)
	fmt.Fprintf(&b, "rebuilt:  heap_live=%.1fMiB rss=%.1fMiB goroutines=%d fds=%d\n", mib(end.HeapLive), mib(end.RSS), end.Goroutines, end.FDs)
	var peakHeap, peakRSS uint64
	var peakG, peakFD int
	for _, s := range samples {
		peakHeap, peakRSS = max(peakHeap, s.HeapLive), max(peakRSS, s.RSS)
		peakG, peakFD = max(peakG, s.Goroutines), max(peakFD, s.FDs)
	}
	if drained.Issued > 0 {
		fmt.Fprintf(&b, "xray ActivityTimer self-deadlocks (handlers stuck for good, see stuckTimers): drained=%d rebuilt=%d peak=%d\n",
			drained.StuckTimers, end.StuckTimers, peakStuck(samples))
		fmt.Fprintf(&b, "retained credentials after the drain: %d issued entries cost %.0f B each (drained heap - rebuilt heap)\n",
			drained.Issued, float64(int64(drained.HeapLive)-int64(end.HeapLive))/float64(drained.Issued))
	}
	fmt.Fprintf(&b, "distinct users installed=%d, distinct (user, inbound) pairs=%d\n", h.unique.Load(), h.pairs.Load())
	fmt.Fprintf(&b, "peaks: heap_live=%.1fMiB rss=%.1fMiB goroutines=%d fds=%d\n", mib(peakHeap), mib(peakRSS), peakG, peakFD)
	h.logf("SUMMARY\n%s", b.String())
	_ = os.WriteFile(filepath.Join(h.cfg.out, "summary.txt"), []byte(b.String()), 0o644)
}

func peakStuck(samples []procSample) int {
	n := 0
	for _, s := range samples {
		n = max(n, s.StuckTimers)
	}
	return n
}

// assertEnd: the pass/fail criteria.
//
// Goroutines/fds: after the drain and an empty Snapshot the process has the
// same shape as at the baseline (same inbounds, no users, same stream), so
// they must match up to a small slack (timers and the runtime's lazily
// started helpers). Heap: after the empty Snapshot xray's instance is new
// and every per-user map was reset, so the live heap (right after a GC) must
// be within heapSlack of the baseline. During the load, the heap may grow
// only with what the agent keeps per distinct user by design: the xray
// stats counters of every user ever installed in the instance (never
// unregistered upstream) and issued credentials (kept 24h), at most
// perUserBytes per distinct (user, inbound) pair.
func (h *soak) assertEnd(t *testing.T, base, drained, end procSample, samples []procSample) {
	const (
		goroutineSlack = 8
		fdSlack        = 8
		heapSlack      = 24 << 20
		perUserBytes   = 2048
	)
	h.vmu.Lock()
	for _, v := range h.violations {
		t.Error(v)
	}
	h.vmu.Unlock()
	if drained.GateConns != 0 || drained.GateLive != 0 || drained.GateAllowed != 0 || drained.GateLimits != 0 {
		t.Errorf("gate not empty after removing every user: conns=%d live keys=%d allowed=%d limits=%d",
			drained.GateConns, drained.GateLive, drained.GateAllowed, drained.GateLimits)
	}
	if drained.Applied != 0 || drained.Counted != 0 || drained.Gone != 0 {
		t.Errorf("per-user maps not empty after the drain: applied=%d counted=%d gone=%d", drained.Applied, drained.Counted, drained.Gone)
	}
	// A handler stuck in xray's ActivityTimer self-deadlock (an upstream
	// bug, see stuckTimers) leaks its goroutine, its connection's socket
	// and, through the goroutine's stack, the old xray instance with every
	// user it held. These failures are real: they are not excused, only
	// explained.
	why := ""
	if end.StuckTimers > 0 {
		why = fmt.Sprintf(" [%d handlers are deadlocked in xray's ActivityTimer.SetTimeout: they and the goroutines waiting for them (about 2 goroutines, 1 socket and the old instance's heap each) are the leak]", end.StuckTimers)
	}
	if end.Goroutines > base.Goroutines+goroutineSlack {
		t.Errorf("goroutines: %d after the drain and a rebuild, baseline %d (+%d allowed)%s", end.Goroutines, base.Goroutines, goroutineSlack, why)
	}
	if end.FDs > base.FDs+fdSlack {
		t.Errorf("open fds: %d after the drain and a rebuild, baseline %d (+%d allowed)%s", end.FDs, base.FDs, fdSlack, why)
	}
	if end.HeapLive > base.HeapLive+heapSlack {
		t.Errorf("live heap %.1f MiB after the drain and a rebuild, baseline %.1f MiB (+%d MiB allowed)%s", mib(end.HeapLive), mib(base.HeapLive), heapSlack>>20, why)
	}
	// During the load: the last sample before the drain.
	var last procSample
	for _, s := range samples {
		if s.T <= h.cfg.duration+time.Minute {
			last = s
		}
	}
	allowed := base.HeapLive + heapSlack + perUserBytes*uint64(h.pairs.Load())
	if last.HeapLive > allowed {
		t.Errorf("live heap %.1f MiB at the end of the load exceeds baseline + %d MiB + %d B x %d distinct (user, inbound) pairs = %.1f MiB",
			mib(last.HeapLive), heapSlack>>20, perUserBytes, h.pairs.Load(), mib(allowed))
	}
}
