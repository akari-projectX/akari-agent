package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"

	"akari/agent/pb"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

const testUser = "11111111-1111-1111-1111-111111111111"

func testSnapshot(port int) (string, []*pb.UserOp) {
	inbounds := fmt.Sprintf(`[{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, port)
	users := []*pb.UserOp{{
		Op:     pb.UserOp_ADD,
		UserId: testUser,
		InboundUsers: []*pb.InboundUser{{
			InboundTag:  "in",
			Protocol:    "vless",
			AccountJson: `{"id":"22222222-2222-2222-2222-222222222222"}`,
		}},
	}}
	return inbounds, users
}

func stamp(inst *core.Instance, v int64) { stampUser(inst, testUser, v) }

func sortStrings(s []string) { sort.Strings(s) }

func stampUser(inst *core.Instance, user string, v int64) {
	sm := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	name := "user>>>" + user + ">>>traffic>>>uplink"
	c := sm.GetCounter(name)
	if c == nil {
		var err error
		if c, err = sm.RegisterCounter(name); err != nil {
			panic(err)
		}
	}
	c.Set(v)
}

// setUplink stamps the running instance's counter for testUser.
func setUplink(t *testing.T, m *CoreManager, v int64) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	stamp(m.instance, v)
}

func uplinkOf(r *pb.TrafficReport) int64 {
	for _, u := range r.GetUsers() {
		if u.UserId == testUser {
			return int64(u.UpBytes)
		}
	}
	return 0
}

func TestRebuildMintsSessionAndReturnsFinalCounters(t *testing.T) {
	m := NewCoreManager()
	s0 := m.SessionID()
	if m.TrafficSnapshot() != nil {
		t.Fatal("no instance: snapshot must be nil")
	}
	inb, users := testSnapshot(freePort(t))
	final, err := m.Rebuild(inb, users)
	if err != nil || final != nil {
		t.Fatalf("first rebuild: final=%v err=%v", final, err)
	}
	s1 := m.SessionID()
	if s1 == s0 {
		t.Fatal("rebuild must mint a new session")
	}
	setUplink(t, m, 777)
	if r := m.TrafficSnapshot(); r.SessionId != s1 || uplinkOf(r) != 777 {
		t.Fatalf("snapshot = %v", r)
	}
	final, err = m.Rebuild(inb, users)
	if err != nil {
		t.Fatal(err)
	}
	if final == nil || final.SessionId != s1 || uplinkOf(final) != 777 {
		t.Fatalf("final report must carry old session + old counters, got %v", final)
	}
	if r := m.TrafficSnapshot(); r.SessionId == s1 || uplinkOf(r) != 0 {
		t.Fatalf("after rebuild: new session with reset counters, got %v", r)
	}
	_, _ = m.Rebuild(`[]`, nil)
}

// Concurrent Rebuild vs TrafficSnapshot: a report may never pair one
// instance's counters with another instance's session. Instance k is
// stamped with counter value k at birth (under the manager lock, via the
// onStart seam) and its session is recorded, so every observed report must
// satisfy value == k(session). Run with -race.
func TestTrafficSnapshotIsAtomicWithRebuild(t *testing.T) {
	m := NewCoreManager()
	inb, users := testSnapshot(freePort(t))
	const rounds = 60

	gen := map[string]int64{} // written under m.mu (inside onStart)
	var k int64
	m.onStart = func(inst *core.Instance) {
		k++
		stamp(inst, k)
		gen[m.sessionID] = k
	}

	var obs []*pb.TrafficReport
	var finals []*pb.TrafficReport
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if r := m.TrafficSnapshot(); r != nil {
				obs = append(obs, r)
			}
		}
	}()

	for i := 0; i < rounds; i++ {
		final, err := m.Rebuild(inb, users)
		if err != nil {
			t.Fatalf("rebuild %d: %v", i, err)
		}
		if final != nil {
			finals = append(finals, final)
		}
	}
	close(stop)
	<-done
	m.onStart = nil
	_, _ = m.Rebuild(`[]`, nil)

	if len(obs) == 0 {
		t.Fatal("no snapshots observed")
	}
	for _, r := range append(obs, finals...) {
		want, ok := gen[r.SessionId]
		if !ok {
			t.Fatalf("report with unknown session %q", r.SessionId)
		}
		if got := uplinkOf(r); got != want {
			t.Fatalf("session of instance %d paired with instance %d counters", want, got)
		}
	}
	if len(finals) != rounds-1 {
		t.Fatalf("want %d final reports, got %d", rounds-1, len(finals))
	}
}

func mustEcho(t *testing.T, c *vlessConn, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: dial: %v", msg, err)
	}
	if err := c.echo(msg); err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

// The heart of UserDelta: removing/rotating one user closes exactly that
// user's live connections, refuses them afterwards, and leaves everyone
// else's connections (and the instance/session) alone.
func TestDeltaRevokesOnlyTheAffectedUsersConnections(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	p := freePort(t)
	if _, err := m.Rebuild(twoInbounds(p, freePort(t)),
		[]*pb.UserOp{vlessUser(userA, "in-a", idA), vlessUser(userB, "in-a", idB)}); err != nil {
		t.Fatal(err)
	}
	session := m.SessionID()

	ca, err := vlessDial(p, idA, echo)
	mustEcho(t, ca, err, "a1")
	defer ca.Close()
	cb, err := vlessDial(p, idB, echo)
	mustEcho(t, cb, err, "b1")
	defer cb.Close()

	final, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userB}})
	if err != nil {
		t.Fatal(err)
	}
	if !cb.closedWithin(3 * time.Second) {
		t.Fatal("removed user's live connection stayed open")
	}
	if err := ca.echo("a2"); err != nil {
		t.Fatalf("other user's connection was disturbed: %v", err)
	}
	if c, err := vlessDial(p, idB, echo); err == nil {
		if c.echo("b2") == nil {
			t.Fatal("removed user can still connect")
		}
		c.Close()
	}
	if final == nil || final.SessionId != session || len(final.Users) != 1 || final.Users[0].UserId != userB ||
		final.Users[0].UpBytes == 0 {
		t.Fatalf("final counters of the removed user = %v", final)
	}
	if m.SessionID() != session {
		t.Fatal("delta rebuilt the instance")
	}

	// Identical REPLACE: a true no-op, the connection survives.
	if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	if err := ca.echo("a3"); err != nil {
		t.Fatalf("identical replace disturbed the connection: %v", err)
	}

	// Rotation: the old credential's live connection is closed and refused,
	// the new one works.
	final, err = m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idB2)})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.closedWithin(3 * time.Second) {
		t.Fatal("rotated credential's live connection stayed open")
	}
	if final == nil || len(final.Users) != 1 || final.Users[0].UserId != userA {
		t.Fatalf("rotation must report the user's counters: %v", final)
	}
	if c, err := vlessDial(p, idA, echo); err == nil {
		if c.echo("old") == nil {
			t.Fatal("old credential still accepted")
		}
		c.Close()
	}
	cn, err := vlessDial(p, idB2, echo)
	mustEcho(t, cn, err, "new")
	cn.Close()
	if m.SessionID() != session {
		t.Fatal("delta rebuilt the instance")
	}
}

// REPLACE removes tags that are no longer listed (and their connections).
func TestReplaceRemovesStaleTags(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	pa, pb2 := freePort(t), freePort(t)
	both := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{
		{InboundTag: "in-a", Protocol: "vless", AccountJson: `{"flow":"","id":"` + idA + `"}`},
		{InboundTag: "in-b", Protocol: "vless", AccountJson: `{"flow":"","id":"` + idA + `"}`},
	}}
	inb := twoInbounds(pa, pb2)
	if _, err := m.Rebuild(inb, []*pb.UserOp{both}); err != nil {
		t.Fatal(err)
	}
	cb, err := vlessDial(pb2, idA, echo)
	mustEcho(t, cb, err, "via b")
	defer cb.Close()
	ca, err := vlessDial(pa, idA, echo)
	mustEcho(t, ca, err, "via a")
	defer ca.Close()

	if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	if !cb.closedWithin(3 * time.Second) {
		t.Fatal("connection on the dropped tag stayed open")
	}
	if err := ca.echo("still a"); err != nil {
		t.Fatalf("kept tag disturbed: %v", err)
	}
	if c, err := vlessDial(pb2, idA, echo); err == nil {
		if c.echo("b again") == nil {
			t.Fatal("dropped tag still accepts the user")
		}
		c.Close()
	}
	want := stateHash(0, inb, []hashRecord{{UserID: userA, Tag: "in-a", Protocol: "vless", Account: `{"flow":"","id":"` + idA + `"}`}})
	if got := m.StateHash(0); got != want {
		t.Fatal("state hash does not reflect the replaced set")
	}
}

// xray keeps a user's counters across RemoveUser+AddUser within one
// instance (nothing unregisters them), so the reported cumulative value
// stays monotonic; and if a counter ever did reset, the guard carries it.
func TestCountersSurviveRemoveAndReAdd(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	p := freePort(t)
	if _, err := m.Rebuild(twoInbounds(p, freePort(t)), []*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	c, err := vlessDial(p, idA, echo)
	mustEcho(t, c, err, "some traffic for A")
	c.Close()
	up := func() uint64 {
		for _, u := range m.TrafficSnapshot().GetUsers() {
			if u.UserId == userA {
				return u.UpBytes
			}
		}
		return 0
	}
	before := up()
	if before == 0 {
		t.Fatal("no traffic counted")
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	if got := up(); got != before {
		t.Fatalf("removed user's counter must still be reported: %d != %d", got, before)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	sm := m.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	raw := counterValue(sm, "user>>>"+userA+">>>traffic>>>uplink")
	m.mu.Unlock()
	if uint64(raw) != before {
		t.Fatalf("xray reset the counter on re-add: raw %d, before %d", raw, before)
	}
	c, err = vlessDial(p, idA, echo)
	mustEcho(t, c, err, "more")
	c.Close()
	after := up()
	if after <= before {
		t.Fatalf("counter not monotonic after re-add: %d <= %d", after, before)
	}
	// Simulated reset (a future core unregistering counters): still
	// monotonic.
	m.mu.Lock()
	_ = sm.UnregisterCounter("user>>>" + userA + ">>>traffic>>>uplink")
	m.mu.Unlock()
	c, err = vlessDial(p, idA, echo)
	mustEcho(t, c, err, "x")
	c.Close()
	if got := up(); got < after {
		t.Fatalf("reported value went backwards after a counter reset: %d < %d", got, after)
	}
}

// The pipe-based Dispatch path (vmess, trojan, mux sub-streams): only the
// installed identity is admitted, revocation cuts the relay, and a relay
// that ends normally releases its tracking entry.
func TestGateDispatchPath(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	echo := echoServer(t)
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)), []*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	gate, installed := m.gate, m.applied[userA]["in-a"].user
	m.mu.Unlock()
	key := gateKey{tag: "in-a", email: userA}
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo))
	ctxFor := func(u *protocol.MemoryUser) context.Context {
		return session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "in-a", User: u})
	}
	roundtrip := func(link *transport.Link, msg string) error {
		if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte(msg))); err != nil {
			return err
		}
		got := ""
		for len(got) < len(msg) {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			got += mb.String()
			buf.ReleaseMulti(mb)
		}
		if got != msg {
			return fmt.Errorf("got %q", got)
		}
		return nil
	}
	eventually := func(cond func() bool, what string) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if cond() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal(what)
	}

	// A different *MemoryUser with the same email (old/rotated credential).
	if _, err := gate.Dispatch(ctxFor(&protocol.MemoryUser{Email: userA}), dest); err != errRevoked {
		t.Fatalf("stale identity admitted: %v", err)
	}

	link, err := gate.Dispatch(ctxFor(installed), dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundtrip(link, "hello"); err != nil {
		t.Fatal(err)
	}
	if gate.Live(key) != 1 {
		t.Fatal("dispatch not tracked")
	}
	// Normal end: close our side, the relay finishes, the entry goes.
	_ = common.Close(link.Writer)
	eventually(func() bool { return gate.Live(key) == 0 }, "finished relay still tracked")

	link, err = gate.Dispatch(ctxFor(installed), dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundtrip(link, "again"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	if err := roundtrip(link, "after revoke"); err == nil {
		t.Fatal("revoked relay still carries data")
	}
	eventually(func() bool { return gate.Live(key) == 0 }, "revoked relay still tracked")
	if _, err := gate.Dispatch(ctxFor(installed), dest); err != errRevoked {
		t.Fatalf("revoked identity admitted: %v", err)
	}
}
