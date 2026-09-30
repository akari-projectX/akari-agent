package main

import (
	"testing"

	"akari/agent/pb"
)

func collect() (*[]*pb.AgentUp, func(*pb.AgentUp) error) {
	var out []*pb.AgentUp
	return &out, func(m *pb.AgentUp) error { out = append(out, m); return nil }
}

// A failed apply must not move the held versions: the post-rebuild Hello
// keeps the previous versions and the Ack carries the attempted ones.
func TestFailedSnapshotKeepsPreviousVersions(t *testing.T) {
	a := NewAgent(&Config{}, "test")
	inb, users := testSnapshot(freePort(t))

	out, send := collect()
	good := &pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
		ConfigVersion: 2, UserVersion: 3, InboundsJson: inb, Users: users}}}
	if err := a.handleDown(send, good); err != nil {
		t.Fatal(err)
	}
	if c, u := a.versions(); c != 2 || u != 3 {
		t.Fatalf("after good snapshot held = %d/%d", c, u)
	}

	*out = nil
	bad := &pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
		ConfigVersion: 5, UserVersion: 6, InboundsJson: `not json`}}}
	if err := a.handleDown(send, bad); err != nil {
		t.Fatal(err)
	}
	if c, u := a.versions(); c != 2 || u != 3 {
		t.Fatalf("failed snapshot moved held versions to %d/%d", c, u)
	}
	var hello *pb.Hello
	var ack *pb.Ack
	for _, m := range *out {
		switch x := m.Msg.(type) {
		case *pb.AgentUp_Hello:
			hello = x.Hello
		case *pb.AgentUp_Ack:
			ack = x.Ack
		}
	}
	if hello == nil || hello.ConfigVersion != 2 || hello.UserVersion != 3 {
		t.Fatalf("hello after failure = %v", hello)
	}
	if ack == nil || ack.Ok || ack.ConfigVersion != 5 || ack.UserVersion != 6 || ack.Error == "" {
		t.Fatalf("ack after failure = %v", ack)
	}
	_, _ = a.core.Rebuild(`[]`, nil)
}
