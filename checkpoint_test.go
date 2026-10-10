package main

import (
	"context"
	"os"
	"testing"
	"time"

	"akari/agent/pb"
)

func TestCheckpointRoundTripAndTornSlot(t *testing.T) {
	dir := t.TempDir()
	c := &checkpointStore{dir: dir}
	r1 := &pb.TrafficReport{SessionId: "s1", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 1, DownBytes: 2}}}
	r2 := &pb.TrafficReport{SessionId: "s1", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 3, DownBytes: 4}}}
	for _, r := range []*pb.TrafficReport{r1, r2} {
		p, err := encodeReports([]*pb.TrafficReport{r})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.write(p); err != nil {
			t.Fatal(err)
		}
	}
	got := (&checkpointStore{dir: dir}).load()
	if len(got) != 1 || got[0].Users[0].UpBytes != 3 {
		t.Fatalf("newest slot not loaded: %v", got)
	}
	// A kill mid-write tears the newest slot: the older one is used.
	newest := c.path(int(c.seq % 2))
	b, _ := os.ReadFile(newest)
	if err := os.WriteFile(newest, b[:len(b)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	got = (&checkpointStore{dir: dir}).load()
	if len(got) != 1 || got[0].Users[0].UpBytes != 1 {
		t.Fatalf("torn slot not skipped: %v", got)
	}
	// A new process continues above any leftover sequence number, so its
	// writes always outrank a slot it could not remove.
	n := &checkpointStore{dir: dir}
	n.load()
	if n.seq < 1 {
		t.Fatalf("seq %d not resumed", n.seq)
	}
	p, _ := encodeReports([]*pb.TrafficReport{{SessionId: "s2", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 9}}}})
	if err := n.write(p); err != nil {
		t.Fatal(err)
	}
	if got = (&checkpointStore{dir: dir}).load(); got[0].SessionId != "s2" {
		t.Fatalf("new write outranked by a leftover slot: %v", got)
	}
	if err := n.write(make([]byte, maxCheckpointPayload+1)); err == nil {
		t.Fatal("oversized checkpoint accepted")
	}
	n.clear()
	if got = (&checkpointStore{dir: dir}).load(); got != nil {
		t.Fatalf("cleared checkpoint still loads: %v", got)
	}
}

// A hard kill (no graceful stop) used to lose every counter not yet
// reported. The checkpoint carries the running instance's counters and the
// unconfirmed finals to the next process, which queues and persists them.
func TestCheckpointSurvivesHardKill(t *testing.T) {
	a := testAgent(t, "127.0.0.1:1")
	dir := t.TempDir()
	a.finalsStore = &finalsStore{dir: dir}
	a.ckpt = &checkpointStore{dir: dir}
	inb, users := testSnapshot(freePort(t))
	if err := a.handleDown(context.Background(), 0, func(*pb.AgentUp) error { return nil },
		snapshotMsg(1, 1, inb, users...)); err != nil {
		t.Fatal(err)
	}
	session := a.core.SessionID()
	a.finals.add(&pb.TrafficReport{SessionId: "older", Users: []*pb.UserTraffic{{UserId: testUser, UpBytes: 7}}})
	a.core.mu.Lock()
	stamp(a.core.instance, 4242)
	a.core.mu.Unlock()

	a.checkpointEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.checkpointLoop(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel() // the "kill": no stopped(), no finals.json
	<-done
	a.core.Teardown()
	if _, err := os.Stat(a.finalsStore.finalsPath()); !os.IsNotExist(err) {
		t.Fatal("finals.json exists; the test would not model a hard kill")
	}

	b := NewAgent(&Config{}, "test", nil)
	b.finalsStore = &finalsStore{dir: dir}
	b.ckpt = &checkpointStore{dir: dir}
	if n := b.resumeCheckpoint(); n != 2 {
		t.Fatalf("recovered %d reports, want 2", n)
	}
	var cur, older bool
	for _, r := range b.finals.all() {
		switch {
		case r.SessionId == session && uplinkOf(r) == 4242:
			cur = true
		case r.SessionId == "older" && uplinkOf(r) == 7:
			older = true
		}
	}
	if !cur || !older {
		t.Fatalf("queued finals %v", b.finals.all())
	}
	// Handed on to finals.json before the checkpoint went.
	if saved := b.finalsStore.load(); len(saved) != 2 {
		t.Fatalf("finals.json has %d reports", len(saved))
	}
	if got := (&checkpointStore{dir: dir}).load(); got != nil {
		t.Fatal("checkpoint not removed after recovery")
	}
}
