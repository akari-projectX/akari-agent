package main

import (
	"context"
	"testing"
	"time"

	"akari/agent/pb"
)

func reportUsers(r *pb.TrafficReport) map[string]uint64 {
	out := map[string]uint64{}
	for _, u := range r.GetUsers() {
		out[u.UserId] = u.UpBytes
	}
	return out
}

// W1: periodic reports carry only users whose counters moved since the
// last one; ResetSent (new stream) makes the next one complete; final
// reports (removal, teardown) are always complete.
func TestTrafficChangesOnlyChangedRows(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	u := []string{benchUserID(1), benchUserID(2), benchUserID(3)}
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)),
		[]*pb.UserOp{benchOp(1, 0), benchOp(2, 0), benchOp(3, 0)}); err != nil {
		t.Fatal(err)
	}
	if r := m.TrafficChanges(); r != nil {
		t.Fatalf("no traffic yet, got %v", r)
	}
	set := func(uid string, v int64) {
		m.mu.Lock()
		stampUser(m.instance, uid, v)
		m.mu.Unlock()
	}
	set(u[0], 10)
	set(u[1], 20)
	set(u[2], 30)
	session := m.SessionID()
	r := m.TrafficChanges()
	if got := reportUsers(r); len(got) != 3 || got[u[0]] != 10 || got[u[2]] != 30 || r.SessionId != session {
		t.Fatalf("first report %v", r)
	}
	if r := m.TrafficChanges(); r != nil {
		t.Fatalf("nothing moved, got %v", r)
	}
	set(u[1], 25)
	if got := reportUsers(m.TrafficChanges()); len(got) != 1 || got[u[1]] != 25 {
		t.Fatalf("only the changed user, got %v", got)
	}
	// Full report always complete; it does not consume the changes.
	if got := reportUsers(m.TrafficSnapshot()); len(got) != 3 || got[u[1]] != 25 {
		t.Fatalf("snapshot %v", got)
	}
	// New stream: complete again, cumulative values.
	m.ResetSent()
	if got := reportUsers(m.TrafficChanges()); len(got) != 3 || got[u[0]] != 10 || got[u[1]] != 25 || got[u[2]] != 30 {
		t.Fatalf("after ResetSent %v", got)
	}
	// Removal: the final report carries the user even though unchanged;
	// the removed user's tail still shows up in later changes.
	final, err := m.ApplyUserOps([]*pb.UserOp{removeOp(u[0])})
	if err != nil {
		t.Fatal(err)
	}
	if got := reportUsers(final); len(got) != 1 || got[u[0]] != 10 {
		t.Fatalf("final %v", got)
	}
	set(u[0], 11)
	if got := reportUsers(m.TrafficChanges()); len(got) != 1 || got[u[0]] != 11 {
		t.Fatalf("removed user's tail %v", got)
	}
	// Teardown: complete final report under the old session.
	fin := m.Teardown()
	if got := reportUsers(fin); len(got) != 3 || fin.SessionId != session {
		t.Fatalf("teardown final %v", fin)
	}
	if m.TrafficChanges() != nil {
		t.Fatal("no instance: no report")
	}
}

// W1 end to end: unchanged users are not resent on a stream, and the first
// periodic report on every new stream is complete.
func TestFirstReportOnNewStreamIsComplete(t *testing.T) {
	inb, users := testSnapshot(freePort(t))
	acked := make(chan struct{})
	stream1 := make(chan []*pb.TrafficReport, 1)
	stream2 := make(chan *pb.TrafficReport, 1)
	f := &fakePanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		if n == 1 {
			_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
				ConfigVersion: 1, UserVersion: 1, InboundsJson: inb, Users: users}}})
		}
		var got []*pb.TrafficReport
		var quiet <-chan time.Time
		for {
			if quiet != nil {
				select {
				case <-quiet:
					stream1 <- got
					return nil // the stream ends: another panel instance takes over
				default:
				}
			}
			m, err := s.Recv()
			if err != nil {
				return nil
			}
			switch x := m.Msg.(type) {
			case *pb.AgentUp_Ack:
				if n == 1 {
					close(acked)
				}
			case *pb.AgentUp_Traffic:
				if n > 1 {
					stream2 <- x.Traffic
					<-s.Context().Done()
					return nil
				}
				got = append(got, x.Traffic)
				if quiet == nil {
					// Ten more ticks with nothing moving.
					quiet = time.After(300 * time.Millisecond)
				}
			}
		}
	}
	a := testAgent(t, startFakePanel(t, f))
	a.trafficEvery = 30 * time.Millisecond
	a.heartbeatEvery = 20 * time.Millisecond // keeps Recv returning
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }()
	select {
	case <-acked:
	case <-time.After(10 * time.Second):
		t.Fatal("no ack")
	}
	a.core.mu.Lock()
	stamp(a.core.instance, 500)
	a.core.mu.Unlock()
	select {
	case got := <-stream1:
		if len(got) != 1 || uplinkOf(got[0]) != 500 {
			t.Fatalf("stream 1: want exactly one report (500), got %v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no traffic on stream 1")
	}
	select {
	case r := <-stream2:
		if uplinkOf(r) != 500 {
			t.Fatalf("first report on stream 2 lacks the unchanged user: %v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no traffic on stream 2: the unchanged user was not reported on the new stream")
	}
}

// W8: a Rebuild skips the remove-everywhere sweep only for a user with
// nothing applied yet; a user listed twice in one Snapshot still ends up
// with exactly the last op's credentials (REPLACE), the first one revoked.
func TestRebuildRepeatedUserStillReplaces(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)),
		[]*pb.UserOp{vlessUser(userA, "in-a", idA), vlessUser(userA, "in-b", idB)}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur := m.applied[userA]; len(cur) != 1 || cur["in-b"].account != `{"flow":"","id":"`+idB+`"}` {
		t.Fatalf("applied %v", cur)
	}
	m.gate.mu.Lock()
	_, onA := m.gate.allowed[gateKey{tag: "in-a", email: userA}]
	_, onB := m.gate.allowed[gateKey{tag: "in-b", email: userA}]
	m.gate.mu.Unlock()
	if onA || !onB {
		t.Fatalf("gate: in-a %v in-b %v", onA, onB)
	}
}
