package main

import (
	"context"
	"testing"

	"akari/agent/pb"
)

func collect() (*[]*pb.AgentUp, func(*pb.AgentUp) error) {
	var out []*pb.AgentUp
	return &out, func(m *pb.AgentUp) error { out = append(out, m); return nil }
}

func snapshotMsg(c, u uint64, inbounds string, users ...*pb.UserOp) *pb.PanelDown {
	return &pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
		ConfigVersion: c, UserVersion: u, InboundsJson: inbounds, Users: users}}}
}

func deltaMsg(base, target [2]uint64, ops ...*pb.UserOp) *pb.PanelDown {
	return &pb.PanelDown{Msg: &pb.PanelDown_Delta{Delta: &pb.UserDelta{
		BaseConfigVersion: base[0], BaseUserVersion: base[1],
		ConfigVersion: target[0], UserVersion: target[1], Ops: ops}}}
}

func removeOp(user string) *pb.UserOp { return &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: user} }

func lastAck(t *testing.T, out []*pb.AgentUp) *pb.Ack {
	t.Helper()
	for i := len(out) - 1; i >= 0; i-- {
		if a, ok := out[i].Msg.(*pb.AgentUp_Ack); ok {
			return a.Ack
		}
	}
	t.Fatal("no ack sent")
	return nil
}

// A failed apply must not move the held versions: the post-rebuild Hello
// keeps the previous versions and the Ack carries the attempted ones.
func TestFailedSnapshotKeepsPreviousVersions(t *testing.T) {
	a := NewAgent(&Config{}, "test")
	defer a.core.Teardown()
	inb, users := testSnapshot(freePort(t))
	ctx := context.Background()

	out, send := collect()
	if err := a.handleDown(ctx, 0, send, snapshotMsg(2, 3, inb, users...)); err != nil {
		t.Fatal(err)
	}
	if c, u := a.versions(); c != 2 || u != 3 {
		t.Fatalf("after good snapshot held = %d/%d", c, u)
	}

	*out = nil
	if err := a.handleDown(ctx, 0, send, snapshotMsg(5, 6, `not json`)); err != nil {
		t.Fatal(err)
	}
	if c, u := a.versions(); c != 2 || u != 3 {
		t.Fatalf("failed snapshot moved held versions to %d/%d", c, u)
	}
	var hello *pb.Hello
	for _, m := range *out {
		if h, ok := m.Msg.(*pb.AgentUp_Hello); ok {
			hello = h.Hello
		}
	}
	if hello == nil || hello.ConfigVersion != 2 || hello.UserVersion != 3 || hello.ProtocolVersion != agentProtocol {
		t.Fatalf("hello after failure = %v", hello)
	}
	ack := lastAck(t, *out)
	if ack.Ok || ack.Reason != pb.Ack_REASON_APPLY_FAILED || ack.ConfigVersion != 5 || ack.UserVersion != 6 ||
		ack.Error == "" || ack.HeldConfigVersion != 2 || ack.HeldUserVersion != 3 {
		t.Fatalf("ack after failure = %v", ack)
	}
}

// The delta decision table: apply iff held == base, no-op iff held ==
// target, otherwise BASE_MISMATCH; failures keep base and dirty the state.
func TestDeltaBaseTargetTable(t *testing.T) {
	a := NewAgent(&Config{}, "test")
	defer a.core.Teardown()
	ctx := context.Background()
	inb := twoInbounds(freePort(t), freePort(t))
	if err := a.handleDown(ctx, 0, func(*pb.AgentUp) error { return nil },
		snapshotMsg(2, 3, inb, vlessUser(userA, "in-a", idA))); err != nil {
		t.Fatal(err)
	}

	type v = [2]uint64
	steps := []struct {
		name       string
		msg        *pb.PanelDown
		wantReason pb.Ack_Reason
		wantHeld   v
		wantUsers  []string // users in the applied set afterwards
	}{
		{"apply on base", deltaMsg(v{2, 3}, v{2, 4}, vlessUser(userB, "in-a", idB)),
			pb.Ack_REASON_OK, v{2, 4}, []string{userA, userB}},
		{"idempotent resend is a no-op", deltaMsg(v{2, 3}, v{2, 4}, vlessUser(userB, "in-a", idB)),
			pb.Ack_REASON_OK, v{2, 4}, []string{userA, userB}},
		{"wrong base", deltaMsg(v{2, 3}, v{2, 5}, removeOp(userA)),
			pb.Ack_REASON_BASE_MISMATCH, v{2, 4}, []string{userA, userB}},
		{"future base", deltaMsg(v{2, 9}, v{2, 10}, removeOp(userA)),
			pb.Ack_REASON_BASE_MISMATCH, v{2, 4}, []string{userA, userB}},
		{"delta may not change config", deltaMsg(v{2, 4}, v{3, 5}, removeOp(userA)),
			pb.Ack_REASON_APPLY_FAILED, v{2, 4}, []string{userA, userB}},
		{"partial failure keeps base", deltaMsg(v{2, 4}, v{2, 5}, removeOp(userB), vlessUser("cccccccc-0000-0000-0000-00000000000c", "no-such-tag", idB2)),
			pb.Ack_REASON_APPLY_FAILED, v{2, 4}, []string{userA}},
		{"dirty after a failed delta", deltaMsg(v{2, 4}, v{2, 6}, removeOp(userA)),
			pb.Ack_REASON_BASE_MISMATCH, v{2, 4}, []string{userA}},
		{"dirty even for the old target", deltaMsg(v{2, 3}, v{2, 4}),
			pb.Ack_REASON_BASE_MISMATCH, v{2, 4}, []string{userA}},
		{"snapshot cleans", snapshotMsg(2, 7, inb, vlessUser(userA, "in-a", idA)),
			pb.Ack_REASON_OK, v{2, 7}, []string{userA}},
		{"deltas resume", deltaMsg(v{2, 7}, v{2, 8}, removeOp(userA)),
			pb.Ack_REASON_OK, v{2, 8}, nil},
	}
	for _, s := range steps {
		out, send := collect()
		if err := a.handleDown(ctx, 0, send, s.msg); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		ack := lastAck(t, *out)
		if ack.Reason != s.wantReason || ack.Ok != (s.wantReason == pb.Ack_REASON_OK) {
			t.Fatalf("%s: ack %v", s.name, ack)
		}
		if c, u := a.versions(); (v{c, u}) != s.wantHeld || (v{ack.HeldConfigVersion, ack.HeldUserVersion}) != s.wantHeld {
			t.Fatalf("%s: held %d/%d, ack held %d/%d, want %v", s.name, c, u, ack.HeldConfigVersion, ack.HeldUserVersion, s.wantHeld)
		}
		got := appliedUsers(a.core)
		if len(got) != len(s.wantUsers) {
			t.Fatalf("%s: applied users %v, want %v", s.name, got, s.wantUsers)
		}
		for i := range got {
			if got[i] != s.wantUsers[i] {
				t.Fatalf("%s: applied users %v, want %v", s.name, got, s.wantUsers)
			}
		}
		// The ack hash describes what actually runs.
		if ack.StateHash != a.core.StateHash(ack.HeldConfigVersion) {
			t.Fatalf("%s: ack hash does not describe the running state", s.name)
		}
	}
}

// Removing a user reports its final counters (current session) before the
// Ack, without a rebuild.
func TestRemovalEmitsFinalCountersBeforeAck(t *testing.T) {
	a := NewAgent(&Config{}, "test")
	defer a.core.Teardown()
	ctx := context.Background()
	inb := twoInbounds(freePort(t), freePort(t))
	_ = a.handleDown(ctx, 0, func(*pb.AgentUp) error { return nil },
		snapshotMsg(1, 1, inb, vlessUser(userA, "in-a", idA), vlessUser(userB, "in-a", idB)))
	session := a.core.SessionID()
	a.core.mu.Lock()
	stampUser(a.core.instance, userB, 4242)
	a.core.mu.Unlock()

	out, send := collect()
	if err := a.handleDown(ctx, 0, send, deltaMsg([2]uint64{1, 1}, [2]uint64{1, 2}, removeOp(userB))); err != nil {
		t.Fatal(err)
	}
	if len(*out) != 2 {
		t.Fatalf("want [traffic, ack], got %v", *out)
	}
	tr, ok := (*out)[0].Msg.(*pb.AgentUp_Traffic)
	if !ok || tr.Traffic.SessionId != session || len(tr.Traffic.Users) != 1 ||
		tr.Traffic.Users[0].UserId != userB || tr.Traffic.Users[0].UpBytes != 4242 {
		t.Fatalf("final report = %v", (*out)[0])
	}
	if ack := lastAck(t, *out); !ack.Ok {
		t.Fatalf("ack %v", ack)
	}
	if a.core.SessionID() != session {
		t.Fatal("a user delta must not rebuild (new session)")
	}
}

func appliedUsers(m *CoreManager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for u := range m.applied {
		out = append(out, u)
	}
	sortStrings(out)
	return out
}

// R10 fallback switch: with remove_mode=rebuild (pushed on the lease
// grant) a delta that removes or rotates a live credential is refused
// untouched (BASE_MISMATCH -> the panel sends a Snapshot); pure additions
// still apply. Gate mode applies all of them in place.
func TestRemoveModeGateVsRebuild(t *testing.T) {
	type v = [2]uint64
	grant := func(mode pb.RemoveMode) *pb.PanelDown {
		return &pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 7200, RemoveMode: mode}}}
	}
	for _, c := range []struct {
		mode             pb.RemoveMode
		add, rot, remove pb.Ack_Reason
	}{
		{pb.RemoveMode_REMOVE_MODE_GATE, pb.Ack_REASON_OK, pb.Ack_REASON_OK, pb.Ack_REASON_OK},
		{pb.RemoveMode_REMOVE_MODE_REBUILD, pb.Ack_REASON_OK, pb.Ack_REASON_BASE_MISMATCH, pb.Ack_REASON_BASE_MISMATCH},
	} {
		a := NewAgent(&Config{}, "test")
		ctx := context.Background()
		nop := func(*pb.AgentUp) error { return nil }
		_ = a.handleDown(ctx, 0, nop, grant(c.mode))
		_ = a.handleDown(ctx, 0, nop, snapshotMsg(2, 1, twoInbounds(freePort(t), freePort(t)), vlessUser(userA, "in-a", idA)))
		step := func(msg *pb.PanelDown) pb.Ack_Reason {
			out, send := collect()
			if err := a.handleDown(ctx, 0, send, msg); err != nil {
				t.Fatal(err)
			}
			return lastAck(t, *out).Reason
		}
		if got := step(deltaMsg(v{2, 1}, v{2, 2}, vlessUser(userB, "in-a", idB))); got != c.add {
			t.Fatalf("%v add: %v", c.mode, got)
		}
		hc, hu := a.versions()
		if got := step(deltaMsg(v{hc, hu}, v{2, 3}, vlessUser(userA, "in-a", idB2))); got != c.rot {
			t.Fatalf("%v rotate: %v", c.mode, got)
		}
		hc, hu = a.versions()
		if got := step(deltaMsg(v{hc, hu}, v{2, 4}, removeOp(userB))); got != c.remove {
			t.Fatalf("%v remove: %v", c.mode, got)
		}
		if c.mode == pb.RemoveMode_REMOVE_MODE_REBUILD && len(appliedUsers(a.core)) != 2 {
			t.Fatal("a refused delta changed the running set")
		}
		a.core.Teardown()
	}
}

// State hash v2 binds the inbounds: same users, other inbounds, other hash.
func TestStateHashBindsInbounds(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	users := []*pb.UserOp{vlessUser(userA, "in-a", idA)}
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)), users); err != nil {
		t.Fatal(err)
	}
	h1 := m.StateHash(1)
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)), users); err != nil {
		t.Fatal(err)
	}
	if m.StateHash(1) == h1 {
		t.Fatal("inbounds not bound into the state hash")
	}
	m.Teardown()
	if m.StateHash(0) != stateHash(0, "", nil) {
		t.Fatal("nothing running must hash with empty inbounds")
	}
}
