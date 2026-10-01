package main

import (
	"fmt"
	"testing"

	"akari/agent/pb"
)

func vmessInbound(port int) string {
	return fmt.Sprintf(`[{"tag":"in-m","listen":"127.0.0.1","port":%d,"protocol":"vmess",`+
		`"settings":{"clients":[]},"streamSettings":{"network":"tcp"}}]`, port)
}

func vmessUser(user, id string) *pb.UserOp {
	return &pb.UserOp{Op: pb.UserOp_ADD, UserId: user, InboundUsers: []*pb.InboundUser{{
		InboundTag: "in-m", Protocol: "vmess", AccountJson: fmt.Sprintf(`{"id":%q}`, id)}}}
}

// vmess is one of the three protocols the panel hands out; until now only
// vless had unit coverage. Add, rotate (same user, new id), remove, and a
// malformed account that must fail the apply instead of being half applied.
func TestVmessUserLifecycle(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	if _, err := m.Rebuild(vmessInbound(freePort(t)), []*pb.UserOp{vmessUser(userA, idA)}); err != nil {
		t.Fatalf("rebuild with a vmess user: %v", err)
	}
	if got := appliedUsers(m); len(got) != 1 || got[0] != userA {
		t.Fatalf("applied %v", got)
	}
	m.mu.Lock()
	first := m.applied[userA]["in-m"].user
	m.mu.Unlock()

	// Rotation: the same user with a new id replaces the identity.
	if _, err := m.ApplyUserOps([]*pb.UserOp{vmessUser(userA, idB)}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	m.mu.Lock()
	second := m.applied[userA]["in-m"].user
	m.mu.Unlock()
	if first == second {
		t.Fatal("rotation kept the old identity object")
	}

	// A second user, then the first one's removal leaves only the second.
	if _, err := m.ApplyUserOps([]*pb.UserOp{vmessUser(userB, idB2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{removeOp(userA)}); err != nil {
		t.Fatal(err)
	}
	if got := appliedUsers(m); len(got) != 1 || got[0] != userB {
		t.Fatalf("after remove: %v", got)
	}

	// Malformed account: the apply fails and nothing half-applied remains.
	bad := &pb.UserOp{Op: pb.UserOp_ADD, UserId: userA, InboundUsers: []*pb.InboundUser{{
		InboundTag: "in-m", Protocol: "vmess", AccountJson: `{"id":5}`}}}
	if _, err := m.ApplyUserOps([]*pb.UserOp{bad}); err == nil {
		t.Fatal("a malformed vmess account was accepted")
	}
	for _, u := range appliedUsers(m) {
		if u == userA {
			t.Fatal("failed add left the user applied")
		}
	}
}
