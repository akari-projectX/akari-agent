package main

import (
	"context"
	"os"
	"testing"
	"time"

	"akari/agent/pb"
)

// A29 (G3): SIGTERM with a live stream: xray is torn down, its final
// counters reach the panel on that stream before it closes, and the
// unconfirmed queue is persisted for the next process.
func TestGracefulStopFlushesFinalCountersAndPersists(t *testing.T) {
	inb, users := testSnapshot(freePort(t))
	acked := make(chan struct{})
	traffic := make(chan *pb.TrafficReport, 8)
	f := &fakePanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
			ConfigVersion: 1, UserVersion: 1, InboundsJson: inb, Users: users}}})
		for {
			m, err := s.Recv()
			if err != nil {
				return nil
			}
			switch x := m.Msg.(type) {
			case *pb.AgentUp_Ack:
				select {
				case <-acked:
				default:
					close(acked)
				}
			case *pb.AgentUp_Traffic:
				traffic <- x.Traffic
			}
		}
	}
	addr := startFakePanel(t, f)
	a := testAgent(t, addr)
	dir := t.TempDir()
	a.finalsStore = &finalsStore{dir: dir}
	a.trafficEvery = time.Hour // only the shutdown path may report

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	select {
	case <-acked:
	case <-time.After(10 * time.Second):
		t.Fatal("no snapshot ack")
	}
	session := a.core.SessionID()
	a.core.mu.Lock()
	stamp(a.core.instance, 555)
	a.core.mu.Unlock()

	cancel() // SIGTERM
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the stop request")
	}
	if a.core.Running() {
		t.Fatal("xray still running after a graceful stop")
	}
	select {
	case r := <-traffic:
		if r.SessionId != session || uplinkOf(r) != 555 {
			t.Fatalf("final report %v, want session %s up 555", r, session)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("final counters were not sent on the live stream")
	}
	saved := a.finalsStore.load()
	if len(saved) != 1 || saved[0].SessionId != session || uplinkOf(saved[0]) != 555 {
		t.Fatalf("persisted finals %v", saved)
	}
}

// A29: no stream (panel unreachable): the final counters are still
// persisted, and a new process loads them back into its queue.
func TestGracefulStopWithoutStreamPersists(t *testing.T) {
	a := testAgent(t, "127.0.0.1:1")
	dir := t.TempDir()
	a.finalsStore = &finalsStore{dir: dir}
	a.dial = func(context.Context, *nodeIdentity) (*dialed, error) { return nil, context.DeadlineExceeded }
	inb, users := testSnapshot(freePort(t))
	if err := a.handleDown(context.Background(), 0, func(*pb.AgentUp) error { return nil },
		snapshotMsg(1, 1, inb, users...)); err != nil {
		t.Fatal(err)
	}
	session := a.core.SessionID()
	a.core.mu.Lock()
	stamp(a.core.instance, 321)
	a.core.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	time.Sleep(100 * time.Millisecond) // a few failed dials
	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if a.core.Running() {
		t.Fatal("xray still running")
	}
	saved := (&finalsStore{dir: dir}).load()
	if len(saved) != 1 || saved[0].SessionId != session || uplinkOf(saved[0]) != 321 {
		t.Fatalf("persisted finals %v", saved)
	}
	// Next process: queue refilled; drained queue removes the file.
	b := NewAgent(&Config{}, "test", nil)
	b.finalsStore = &finalsStore{dir: dir}
	for _, r := range b.finalsStore.load() {
		b.finals.add(r)
	}
	b.finalsPersisted.Store(true)
	if b.finals.len() != 1 {
		t.Fatal("persisted report not re-queued")
	}
	b.persistFinalsLocked("test")
	b.finals.items = nil
	b.persistFinalsLocked("empty") // nothing owed: the file goes
	if _, err := os.Stat(b.finalsStore.finalsPath()); !os.IsNotExist(err) {
		t.Fatalf("finals file not removed once nothing is owed: %v", err)
	}
}
