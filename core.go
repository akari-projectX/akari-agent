package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	"akari/agent/pb"
)

// The proxyman handler exposes the running proxy; the protocol inbounds
// (vless/vmess Handler, trojan Server) own the user store.
type proxyExposer interface {
	GetInbound() proxy.Inbound
}

type userManager interface {
	AddUser(ctx context.Context, u *protocol.MemoryUser) error
	RemoveUser(ctx context.Context, email string) error
}

func userStore(handler inbound.Handler) (userManager, error) {
	exposer, ok := handler.(proxyExposer)
	if !ok {
		return nil, fmt.Errorf("handler does not expose its proxy")
	}
	store, ok := exposer.GetInbound().(userManager)
	if !ok {
		return nil, fmt.Errorf("proxy inbound does not support dynamic users")
	}
	return store, nil
}

// appliedCred is one credential actually installed on one inbound.
type appliedCred struct {
	protocol string
	account  string // account_json verbatim (hashed as-is)
	user     *protocol.MemoryUser
}

// monoCounter keeps a reported counter monotonic within a session even if
// the underlying xray counter were ever reset (see readCounter).
type monoCounter struct {
	lastRaw int64
	offset  int64
}

// CoreManager owns the embedded xray-core instance. The agent is a
// supervisor: it (re)builds the instance from panel-pushed snapshots and
// applies per-user changes in place (UserDelta), without restarting it.
type CoreManager struct {
	mu       sync.Mutex
	instance *core.Instance
	gate     *gateDispatcher
	// liveGate mirrors gate for lock-free readers (heartbeat), so a
	// heartbeat never waits for a Rebuild holding mu.
	liveGate atomic.Pointer[gateDispatcher]
	tags     []string
	// kinds: what each running inbound is (protocols.go).
	kinds map[string]inboundKind
	// inboundsJSON is the running instance's Snapshot.inbounds_json
	// verbatim ("" when none runs); bound into the state hash.
	inboundsJSON string
	// sessionID names the lifetime of the current traffic counters. It is
	// only changed under mu, together with the instance, so a
	// TrafficSnapshot can never pair one instance's counters with another
	// instance's session (the panel bills by (node, user, session)).
	sessionID string
	// applied is what is really installed: user -> inbound tag -> cred.
	// It feeds the state hash, so it only records successful adds.
	applied map[string]map[string]appliedCred
	// issued: inbound tag -> user -> the last credential installed for
	// the user on that tag in this instance, live or not (W9). A re-add of
	// the identical credential reuses its *MemoryUser, so sessions a
	// client kept across the removal (a Hysteria 2 QUIC connection, a mux
	// connection: authenticated once, their streams carry that pointer)
	// are admitted again. On shrink-unsafe (Shadowsocks 2022) tags every
	// issued credential is still in xray's user table: the ones not live
	// are tombstones (see shrinkUnsafe). Reset with the instance.
	issued map[string]map[string]appliedCred
	// tombs: shrink-unsafe tag -> number of tombstones on it.
	tombs map[string]int
	// counted: every email with counters in this instance, including users
	// removed since (xray keeps their counters; the tail is still billed).
	counted map[string]struct{}
	mono    map[string]*monoCounter
	// nodeCert: where TLS inbounds naming the node certificate credential
	// files read the ACME-managed certificate (protocol 6); nil = no
	// rewrite (the files the admin installs). Set before each Rebuild.
	nodeCert *certFiles
	// acmeTags: inbounds of the running instance that serve nodeCert;
	// acmePlaceholder: nodeCert held the self-signed placeholder when the
	// instance was built (the first CA certificate swaps those inbounds,
	// see ReloadInbounds).
	acmeTags        []string
	acmePlaceholder bool
	// onStart is a test seam, called under mu right after a new instance
	// is installed. Always nil in production.
	onStart func(*core.Instance)
}

func NewCoreManager() *CoreManager {
	m := &CoreManager{sessionID: newSessionID()}
	m.resetUsersLocked()
	return m
}

func (m *CoreManager) resetUsersLocked() {
	m.applied = make(map[string]map[string]appliedCred)
	m.issued = make(map[string]map[string]appliedCred)
	m.tombs = make(map[string]int)
	m.counted = make(map[string]struct{})
	m.mono = make(map[string]*monoCounter)
}

// SessionID returns the session the current counters belong to.
func (m *CoreManager) SessionID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionID
}

// UserCount returns how many users have at least one live credential.
func (m *CoreManager) UserCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.applied)
}

// Connections returns how many proxied dispatches the gate tracks right
// now (0 when no instance runs). Heartbeat.connections.
func (m *CoreManager) Connections() uint64 {
	g := m.liveGate.Load()
	if g == nil {
		return 0
	}
	return uint64(g.LiveTotal())
}

// LiveStats returns the gate's tracked dispatches and the distinct users
// among them (0, 0 when no instance runs).
func (m *CoreManager) LiveStats() (conns, users uint64) {
	g := m.liveGate.Load()
	if g == nil {
		return 0, 0
	}
	c, u := g.LiveStats()
	return uint64(c), uint64(u)
}

// Running reports whether an xray instance is up.
func (m *CoreManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instance != nil
}

// stopLocked closes the current instance and returns its final counters
// (old session), or nil. A fresh session id is minted: counters restart
// with whatever instance comes next (or none).
func (m *CoreManager) stopLocked() *pb.TrafficReport {
	var final *pb.TrafficReport
	if m.instance != nil {
		if counters := m.countersLocked(nil); len(counters) > 0 {
			final = &pb.TrafficReport{Users: counters, SessionId: m.sessionID}
		}
		_ = m.instance.Close()
		m.instance = nil
		m.gate = nil
		m.liveGate.Store(nil)
		m.tags = nil
		m.kinds = nil
		m.acmeTags = nil
		m.acmePlaceholder = false
	}
	m.inboundsJSON = ""
	m.sessionID = newSessionID()
	m.resetUsersLocked()
	return final
}

// Teardown stops xray (lease expiry). Returns the final counters of the
// stopped instance under its (old) session, or nil.
func (m *CoreManager) Teardown() *pb.TrafficReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

// Rebuild stops the current instance (if any) and starts a new one from the
// panel's desired state. Traffic counters reset here, so a fresh session id
// is minted under the same lock. The old instance's final counters (tagged
// with the old session) are returned so the caller can report them instead
// of losing up to one reporting interval of traffic; nil if there were none.
func (m *CoreManager) Rebuild(inboundsJSON string, users []*pb.UserOp) (*pb.TrafficReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	final := m.stopLocked()

	b, err := newInstanceWith(inboundsJSON, m.nodeCert)
	if err != nil {
		return final, err
	}

	m.instance = b.inst
	m.gate = b.gate
	m.liveGate.Store(b.gate)
	m.tags = b.tags
	m.kinds = b.kinds
	m.acmeTags = b.acmeTags
	m.acmePlaceholder = m.nodeCert != nil && m.nodeCert.placeholder && len(b.acmeTags) > 0
	m.inboundsJSON = inboundsJSON
	if m.onStart != nil {
		m.onStart(b.inst)
	}

	var firstErr error
	for _, op := range users {
		if _, err := m.applyOpLocked(op); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return final, firstErr
}

// SetNodeCert sets where the next Rebuild points TLS inbounds that name
// the node certificate credential files (nil: leave them as they are).
func (m *CoreManager) SetNodeCert(f *certFiles) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f == nil {
		m.nodeCert = nil
		return
	}
	c := *f
	m.nodeCert = &c
}

// ServesPlaceholder reports whether the running instance was built while
// the node certificate was the self-signed placeholder.
func (m *CoreManager) ServesPlaceholder() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instance != nil && m.acmePlaceholder
}

// ReloadInbounds swaps the handlers of the inbounds serving the node
// certificate for fresh ones built from the same config, so they read the
// certificate files again at once (the first CA certificate after the
// placeholder). Every other inbound, the session, the counters and the
// gate stay as they are; each live user is re-added to the new handler
// with its existing *MemoryUser (same gate identity). Connections on the
// swapped inbounds may drop (a Hysteria 2 listener closes its QUIC
// connections); those inbounds only served the placeholder until now.
// Renewals never come here: xray re-reads the files by itself.
func (m *CoreManager) ReloadInbounds() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil || len(m.acmeTags) == 0 {
		return nil
	}
	var inbounds []json.RawMessage
	if err := json.Unmarshal([]byte(m.inboundsJSON), &inbounds); err != nil {
		return fmt.Errorf("parse inbounds: %w", err)
	}
	cfg, _, _, err := buildConfig(inbounds, m.nodeCert)
	if err != nil {
		return err
	}
	im, err := m.manager()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, tag := range m.acmeTags {
		var hc *core.InboundHandlerConfig
		for _, in := range cfg.Inbound {
			if in.Tag == tag {
				hc = in
				break
			}
		}
		if hc == nil {
			return fmt.Errorf("inbound %q: not in the config", tag)
		}
		if err := im.RemoveHandler(ctx, tag); err != nil {
			return fmt.Errorf("inbound %q: remove handler: %w", tag, err)
		}
		if err := core.AddInboundHandler(m.instance, hc); err != nil {
			return fmt.Errorf("inbound %q: add handler: %w", tag, err)
		}
		store, err := m.store(tag)
		if err != nil {
			return err
		}
		for uid, c := range m.issued[tag] {
			if _, live := m.applied[uid][tag]; !live {
				continue
			}
			if err := store.AddUser(ctx, c.user); err != nil {
				return fmt.Errorf("inbound %q: re-add user %s: %w", tag, uid, err)
			}
		}
	}
	m.acmePlaceholder = false
	return nil
}

// WouldDropCredential reports whether ops would remove or change a live
// credential (removal/rotation), as opposed to pure additions.
func (m *CoreManager) WouldDropCredential(ops []*pb.UserOp) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, op := range ops {
		cur := m.applied[op.GetUserId()]
		if len(cur) == 0 {
			continue
		}
		if op.GetOp() != pb.UserOp_ADD {
			return true
		}
		want := map[string]*pb.InboundUser{}
		for _, iu := range op.GetInboundUsers() {
			want[iu.GetInboundTag()] = iu
		}
		for tag, c := range cur {
			w, ok := want[tag]
			if !ok || w.GetProtocol() != c.protocol || w.GetAccountJson() != c.account {
				return true
			}
		}
	}
	return false
}

// WouldShrinkUnsafe reports whether ops cannot be applied in place on an
// inbound whose users must not leave its user table while it runs
// (shrinkUnsafe: Shadowsocks 2022 multi-user). There a removal only
// tombstones the credential (gate-revoked, kept in xray's table) and a
// re-add of the SAME credential revives it, but the table holds one entry
// per user (xray refuses a duplicate email), so a different credential for
// a user the table already holds (rotation; re-add with a new key) cannot
// be installed. Neither can a removal that would push a tag's tombstones
// past maxTombstones. Such deltas are refused whatever the remove mode; the
// Snapshot that follows rebuilds (and compacts).
func (m *CoreManager) WouldShrinkUnsafe(ops []*pb.UserOp) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The ops in order, over a scratch view of the shrink-unsafe tags.
	type entry struct {
		cred   appliedCred
		issued bool
		live   bool
	}
	view := map[gateKey]entry{}
	tombs := map[string]int{}
	size := map[string]int{}
	for _, tag := range m.tags {
		if shrinkUnsafe(m.kinds[tag]) {
			tombs[tag] = m.tombs[tag]
			size[tag] = len(m.issued[tag])
		}
	}
	for _, op := range ops {
		uid := op.GetUserId()
		want := map[string]*pb.InboundUser{}
		if op.GetOp() == pb.UserOp_ADD {
			for _, iu := range op.GetInboundUsers() {
				want[iu.GetInboundTag()] = iu
			}
		}
		for tag := range tombs {
			key := gateKey{tag: tag, email: uid}
			e, seen := view[key]
			if !seen {
				e.cred, e.issued = m.issued[tag][uid]
				_, e.live = m.applied[uid][tag]
			}
			w, wanted := want[tag]
			same := wanted && e.issued && w.GetProtocol() == e.cred.protocol && w.GetAccountJson() == e.cred.account
			switch {
			case wanted && e.issued && !same:
				return true // rotation, or re-add with another credential
			case wanted && e.issued && !e.live:
				tombs[tag]-- // revive the tombstone
				e.live = true
			case wanted && !e.issued:
				size[tag]++ // appended
				e.cred = appliedCred{protocol: w.GetProtocol(), account: w.GetAccountJson()}
				e.issued, e.live = true, true
			case !wanted && e.live:
				tombs[tag]++
				e.live = false
			}
			view[key] = e
		}
	}
	for tag, n := range tombs {
		if n > m.tombs[tag] && n > maxTombstones(size[tag]-n) {
			return true
		}
	}
	return false
}

// tombstoneFloor: tombstones a shrink-unsafe tag may always hold. A test
// seam (var), constant in production.
var tombstoneFloor = 1024

// maxTombstones bounds a tag's tombstones by its live users: at most
// max(tombstoneFloor, live). Each costs a MemoryUser and a sing-shadowsocks
// key entry (~1 KB) and inflates the O(table) rebuild xray does on every
// AddUser; the handshake lookup is a hash map, so it costs no CPU there.
// Past the bound a removal is refused and the panel's Snapshot compacts.
func maxTombstones(live int) int { return max(tombstoneFloor, live) }

// ApplyUserOps applies UserDelta ops to the running instance, continuing
// past failures (every op is idempotent; `applied` records what really took
// effect). Users who lost a live credential get their final counters
// returned (current session), read after their connections were closed.
func (m *CoreManager) ApplyUserOps(ops []*pb.UserOp) (*pb.TrafficReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil, fmt.Errorf("core not started")
	}
	var firstErr error
	touched := map[string]struct{}{}
	for _, op := range ops {
		lost, err := m.applyOpLocked(op)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if lost {
			touched[op.GetUserId()] = struct{}{}
		}
	}
	var final *pb.TrafficReport
	if len(touched) > 0 {
		final = &pb.TrafficReport{Users: m.countersLocked(touched), SessionId: m.sessionID}
	}
	return final, firstErr
}

// applyOpLocked applies one op with REPLACE semantics. Returns whether a
// credential that was live got dropped or swapped.
func (m *CoreManager) applyOpLocked(op *pb.UserOp) (lost bool, err error) {
	uid := op.GetUserId()
	if uid == "" {
		return false, fmt.Errorf("user op without user id")
	}
	want := map[string]*pb.InboundUser{}
	switch op.GetOp() {
	case pb.UserOp_ADD:
		for _, iu := range op.GetInboundUsers() {
			want[iu.GetInboundTag()] = iu // later entry for a tag wins
		}
	case pb.UserOp_REMOVE:
	default:
		return false, fmt.Errorf("unknown user op %d", op.GetOp())
	}

	cur := m.applied[uid]
	if cur == nil {
		cur = make(map[string]appliedCred)
	}
	// 1. Drop everything not kept verbatim — on EVERY inbound of the
	// instance, not only the ones we believe hold the user, so a stale or
	// rotated credential can never stay live.
	for _, tag := range m.tags {
		if c, ok := cur[tag]; ok {
			if w, keep := want[tag]; keep && w.GetProtocol() == c.protocol && w.GetAccountJson() == c.account {
				continue
			}
			lost = true
			if shrinkUnsafe(m.kinds[tag]) {
				m.tombs[tag]++ // stays in xray's table, refused by the gate
			}
		}
		m.gate.Revoke(gateKey{tag: tag, email: uid})
		delete(cur, tag)
		if shrinkUnsafe(m.kinds[tag]) {
			continue // never RemoveUser here: it moves other users' indices
		}
		if store, e := m.store(tag); e == nil {
			_ = store.RemoveUser(context.Background(), uid) // not-found is fine
		}
	}
	// 2. The user's rate limit, before any new credential can admit an
	// unthrottled connection (a REMOVE, or an ADD that installs nothing,
	// ends with no limit below).
	if len(want) > 0 {
		m.gate.SetLimit(uid, op.GetSpeedLimitBytesPerSec())
	}
	// 3. Install what is missing, in a deterministic order.
	tags := make([]string, 0, len(want))
	for tag := range want {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if _, ok := cur[tag]; ok {
			continue // identical credential already live: untouched
		}
		w := want[tag]
		if e := m.addUserLocked(tag, w, uid, cur); e != nil && err == nil {
			err = e
		}
	}
	if len(cur) > 0 {
		m.applied[uid] = cur
		m.counted[uid] = struct{}{}
	} else {
		delete(m.applied, uid)
		m.gate.SetLimit(uid, 0)
	}
	return lost, err
}

func (m *CoreManager) store(tag string) (userManager, error) {
	im, err := m.manager()
	if err != nil {
		return nil, err
	}
	handler, err := im.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("inbound %q: %w", tag, err)
	}
	store, err := userStore(handler)
	if err != nil {
		return nil, fmt.Errorf("inbound %q: %w", tag, err)
	}
	return store, nil
}

func (m *CoreManager) addUserLocked(tag string, iu *pb.InboundUser, uid string, cur map[string]appliedCred) error {
	key := gateKey{tag: tag, email: uid}
	unsafe := shrinkUnsafe(m.kinds[tag])
	prev, had := m.issued[tag][uid]
	same := had && prev.protocol == iu.GetProtocol() && prev.account == iu.GetAccountJson()
	if unsafe && had {
		if !same {
			// One table entry per user: a new credential needs a new
			// instance (WouldShrinkUnsafe refuses such deltas first).
			return fmt.Errorf("inbound %q: user %s already has another shadowsocks credential in this instance; needs a snapshot", tag, uid)
		}
		// Revive the tombstone: it never left xray's table.
		m.gate.Allow(key, prev.user)
		m.tombs[tag]--
		cur[tag] = prev
		m.counted[uid] = struct{}{}
		return nil
	}
	var memoryUser *protocol.MemoryUser
	if same {
		memoryUser = prev.user
	} else {
		user, err := buildUser(iu.GetProtocol(), iu.GetAccountJson(), uid, m.kinds[tag])
		if err != nil {
			return fmt.Errorf("inbound %q: %w", tag, err)
		}
		if memoryUser, err = user.ToMemoryUser(); err != nil {
			return fmt.Errorf("materialize user: %w", err)
		}
	}
	store, err := m.store(tag)
	if err != nil {
		return err
	}
	// Admit the new identity before the validator can authenticate it.
	m.gate.Allow(key, memoryUser)
	if !unsafe {
		_ = store.RemoveUser(context.Background(), uid)
	}
	if err := store.AddUser(context.Background(), memoryUser); err != nil {
		m.gate.Revoke(key)
		return fmt.Errorf("add user to inbound %q: %w", tag, err)
	}
	c := appliedCred{protocol: iu.GetProtocol(), account: iu.GetAccountJson(), user: memoryUser}
	cur[tag] = c
	if m.issued[tag] == nil {
		m.issued[tag] = make(map[string]appliedCred)
	}
	m.issued[tag][uid] = c
	m.counted[uid] = struct{}{}
	m.registerCountersLocked(uid)
	return nil
}

// registerCountersLocked creates the user's xray traffic counters up front.
// xray registers them lazily per connection with a check-then-register
// (stats.GetOrRegisterCounter) that is not atomic: of two first connections
// of a user racing, the loser gets a nil counter and relays uncounted —
// bytes never billed. Registered here, under mu and before the user can
// connect, every connection finds the counter and the race cannot occur.
func (m *CoreManager) registerCountersLocked(uid string) {
	if m.instance == nil {
		return
	}
	sm, ok := m.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return
	}
	for _, dir := range []string{"uplink", "downlink"} {
		_, _ = stats.GetOrRegisterCounter(sm, "user>>>"+uid+">>>traffic>>>"+dir)
	}
}

// Tombstones returns the number of tombstones on tag (tests, bench).
func (m *CoreManager) Tombstones(tag string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tombs[tag]
}

func (m *CoreManager) manager() (inbound.Manager, error) {
	im, ok := m.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return nil, fmt.Errorf("xray core has no inbound manager")
	}
	return im, nil
}

// StateHash hashes what is actually installed, bound to configVersion (see
// agent.proto "State hash").
func (m *CoreManager) StateHash(configVersion uint64) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var recs []hashRecord
	for uid, tags := range m.applied {
		for tag, c := range tags {
			recs = append(recs, hashRecord{UserID: uid, Tag: tag, Protocol: c.protocol, Account: c.account})
		}
	}
	return stateHash(configVersion, m.inboundsJSON, recs)
}

// TrafficSnapshot returns the current session id together with the
// cumulative per-user counters of the instance that session names. Both are
// read under mu, so a concurrent Rebuild cannot split them.
func (m *CoreManager) TrafficSnapshot() *pb.TrafficReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil
	}
	return &pb.TrafficReport{Users: m.countersLocked(nil), SessionId: m.sessionID}
}

// countersLocked reads per-user counters of m.instance for `only` (nil =
// every counted email). Caller holds mu.
func (m *CoreManager) countersLocked(only map[string]struct{}) []*pb.UserTraffic {
	sm, ok := m.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return nil
	}
	set := only
	if set == nil {
		set = m.counted
	}
	emails := make([]string, 0, len(set))
	for e := range set {
		emails = append(emails, e)
	}
	sort.Strings(emails)

	var out []*pb.UserTraffic
	for _, email := range emails {
		up := m.readCounter(sm, "user>>>"+email+">>>traffic>>>uplink")
		down := m.readCounter(sm, "user>>>"+email+">>>traffic>>>downlink")
		if up == 0 && down == 0 {
			continue
		}
		out = append(out, &pb.UserTraffic{
			UserId:    email,
			UpBytes:   uint64(up),
			DownBytes: uint64(down),
		})
	}
	return out
}

// readCounter returns a session-monotonic value for an xray counter. xray
// v26.3.27 never unregisters or resets per-user counters when a user is
// removed and re-added (RemoveUser only touches the validator; nothing
// calls stats.UnregisterCounter), so the offset stays 0 in practice. It is a
// guard against a future core doing so: any drop is carried as an offset,
// so the cumulative value the panel bills per session never goes backwards.
func (m *CoreManager) readCounter(sm stats.Manager, name string) int64 {
	raw := counterValue(sm, name)
	st := m.mono[name]
	if st == nil {
		st = &monoCounter{}
		m.mono[name] = st
	}
	if raw < st.lastRaw {
		st.offset += st.lastRaw
	}
	st.lastRaw = raw
	return raw + st.offset
}

func counterValue(sm stats.Manager, name string) int64 {
	c := sm.GetCounter(name)
	if c == nil {
		return 0
	}
	return c.Value()
}

// refuseFakeDNS is the authoritative FakeDNS check (the panel's JSON check
// is only a courtesy): it inspects what xray itself parsed, after its
// case-insensitive key matching, merging and string-list handling. The
// gate wraps a DefaultDispatcher without a FakeDNS engine, so fakedns
// sniffing would silently misroute (R10 F4, R12).
func refuseFakeDNS(cfg *core.Config) error {
	for _, in := range cfg.Inbound {
		if in.ReceiverSettings == nil {
			continue
		}
		msg, err := in.ReceiverSettings.GetInstance()
		if err != nil {
			return fmt.Errorf("inbound %q: receiver settings: %w", in.Tag, err)
		}
		rc, ok := msg.(*proxyman.ReceiverConfig)
		if !ok || rc.SniffingSettings == nil {
			continue
		}
		for _, o := range rc.SniffingSettings.DestinationOverride {
			if strings.Contains(strings.ToLower(o), "fakedns") {
				return fmt.Errorf("inbound %q: fakedns sniffing is not supported by this agent", in.Tag)
			}
		}
	}
	return nil
}

// built is a started instance and what newInstance learned about it.
type built struct {
	inst  *core.Instance
	gate  *gateDispatcher
	tags  []string
	kinds map[string]inboundKind
	// acmeTags: inbounds pointed at the ACME-managed node certificate.
	acmeTags []string
}

func newInstance(inboundsJSON string) (*built, error) {
	return newInstanceWith(inboundsJSON, nil)
}

// buildConfig turns the inbounds into xray's config (gate in place of the
// dispatcher), with node certificate entries pointed at cert (if set).
func buildConfig(inbounds []json.RawMessage, cert *certFiles) (*core.Config, map[string]inboundKind, []string, error) {
	var acmeTags []string
	if cert != nil {
		var err error
		if inbounds, acmeTags, err = rewriteCertPaths(inbounds, *cert); err != nil {
			return nil, nil, nil, err
		}
	}
	full := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"protocol": "freedom"},
		},
		// Per-user traffic counters live behind these policy switches.
		// No per-inbound counters (W8): nothing reads them, and with them
		// on proxyman wraps every accepted connection in a
		// stat.CounterConnection, which hides the transport's identity
		// from the proxy — xray's Hysteria inbound finds its user with
		// conn.(interface{ User() }) and, wrapped, ran every client as an
		// anonymous user: unbilled and invisible to the gate.
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
		},
		"stats": map[string]any{},
	}
	b, err := json.Marshal(full)
	if err != nil {
		return nil, nil, nil, err
	}

	jsonConfig, err := confserial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode xray config: %w", err)
	}
	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build xray config: %w", err)
	}
	if err := refuseFakeDNS(pbConfig); err != nil {
		return nil, nil, nil, err
	}
	if err := multiUserShadowsocks(inbounds, pbConfig); err != nil {
		return nil, nil, nil, err
	}
	kinds, err := inboundKinds(pbConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	// Swap xray's dispatcher for the gate (same slot in the app list, so
	// every inbound resolves the gate when it is created).
	stock := commonserial.GetMessageType(&dispatcher.Config{})
	swapped := false
	for i, app := range pbConfig.App {
		if app.GetType() == stock {
			pbConfig.App[i] = commonserial.ToTypedMessage(&pb.GateDispatcherConfig{})
			swapped = true
		}
	}
	if !swapped {
		return nil, nil, nil, fmt.Errorf("xray config has no dispatcher to replace")
	}
	return pbConfig, kinds, acmeTags, nil
}

func newInstanceWith(inboundsJSON string, cert *certFiles) (*built, error) {
	var inbounds []json.RawMessage
	if err := json.Unmarshal([]byte(inboundsJSON), &inbounds); err != nil {
		return nil, fmt.Errorf("parse inbounds: %w", err)
	}
	if len(inbounds) == 0 {
		inbounds = []json.RawMessage{}
	}
	pbConfig, kinds, acmeTags, err := buildConfig(inbounds, cert)
	if err != nil {
		return nil, err
	}
	inst, err := core.New(pbConfig)
	if err != nil {
		return nil, fmt.Errorf("build xray instance: %w", err)
	}
	gate, ok := inst.GetFeature(routing.DispatcherType()).(*gateDispatcher)
	if !ok {
		_ = inst.Close()
		return nil, fmt.Errorf("gate dispatcher not installed")
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, fmt.Errorf("start xray instance: %w", err)
	}

	tags := make([]string, 0, len(inbounds))
	for _, raw := range inbounds {
		var probe struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.Tag != "" {
			tags = append(tags, probe.Tag)
		}
	}
	return &built{inst: inst, gate: gate, tags: tags, kinds: kinds, acmeTags: acmeTags}, nil
}
