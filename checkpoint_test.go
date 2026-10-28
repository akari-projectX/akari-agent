package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
)

// checkpointFrame is a write frame (header room + payload) for reports,
// encoded with proto.Marshal: the reference the production encoder must
// match byte for byte.
func checkpointFrame(t *testing.T, reports ...*pb.TrafficReport) []byte {
	t.Helper()
	frame := make([]byte, checkpointHdr)
	for _, r := range reports {
		b, err := proto.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		frame = binary.AppendUvarint(frame, uint64(len(b)))
		frame = append(frame, b...)
	}
	return frame
}

// The protowire encoder must produce exactly proto.Marshal's bytes, so
// checkpoints written by either read back the same: zero values (empty
// user id, zero directions, no session), large varints, many users, and
// final reports present or absent.
func TestCheckpointEncodingIsProto(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	many := make([]*pb.UserTraffic, 3000)
	for i := range many {
		many[i] = &pb.UserTraffic{UserId: fmt.Sprintf("user-%d", i), UpBytes: rng.Uint64() >> rng.Intn(64), DownBytes: rng.Uint64() >> rng.Intn(64)}
	}
	cases := []struct {
		name   string
		finals []*pb.TrafficReport
		live   *pb.TrafficReport // the counters' report (monotonic_ms 0)
	}{
		{name: "nothing"},
		{name: "zero values", live: &pb.TrafficReport{Users: []*pb.UserTraffic{{}, {UserId: "u"}, {UpBytes: 1}, {DownBytes: 1}}}},
		{name: "live only", live: &pb.TrafficReport{SessionId: "s", Users: many}},
		{name: "finals only", finals: []*pb.TrafficReport{
			{SessionId: "a", MonotonicMs: 1 << 40, Users: many[:10]},
			{Users: []*pb.UserTraffic{{UserId: "x", UpBytes: ^uint64(0), DownBytes: 127}}},
			{SessionId: "empty"},
		}},
		{name: "finals and live", finals: []*pb.TrafficReport{{SessionId: "old", MonotonicMs: 5, Users: many[:500]}},
			live: &pb.TrafficReport{SessionId: "s", Users: many[500:]}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := checkpointFrame(t, tc.finals...)[checkpointHdr:]
			got, rows := appendReports(nil, tc.finals, nil)
			if tc.live != nil {
				want = append(want, checkpointFrame(t, tc.live)[checkpointHdr:]...)
				rows = rows[:0]
				for _, u := range tc.live.Users {
					rows = append(rows, checkpointRow{userID: u.UserId, up: u.UpBytes, down: u.DownBytes})
				}
				got = appendReport(got, tc.live.SessionId, 0, rows)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("appendReports encodes %d bytes, proto.Marshal %d bytes; first difference at %d", len(got), len(want), firstDiff(got, want))
			}
			back, err := decodeReports(got)
			if err != nil {
				t.Fatalf("decodeReports: %v", err)
			}
			if n := len(tc.finals) + boolToInt(tc.live != nil); len(back) != n {
				t.Fatalf("decodeReports returned %d reports, want %d", len(back), n)
			}
		})
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// A tick writes only when a counter moved, the final queue changed or the
// previous write failed; an idle tick leaves the slots alone.
func TestCheckpointWritesOnlyChanges(t *testing.T) {
	a := testAgent(t, "127.0.0.1:1")
	dir := t.TempDir()
	a.ckpt = &checkpointStore{dir: dir}
	a.checkpointLocked()
	if a.ckpt.seq != 0 {
		t.Fatalf("nothing owed, but checkpoint written (seq %d)", a.ckpt.seq)
	}
	inb, users := testSnapshot(freePort(t))
	if err := a.handleDown(context.Background(), 0, func(*pb.AgentUp) error { return nil },
		snapshotMsg(1, 1, inb, users...)); err != nil {
		t.Fatal(err)
	}
	session := a.core.SessionID()
	loaded := func() []*pb.TrafficReport {
		t.Helper()
		return (&checkpointStore{dir: dir}).load()
	}
	set := func(v int64) {
		a.core.mu.Lock()
		stamp(a.core.instance, v)
		a.core.mu.Unlock()
	}

	set(10)
	a.checkpointLocked()
	if a.ckpt.seq != 1 || len(loaded()) != 1 || uplinkOf(loaded()[0]) != 10 {
		t.Fatalf("seq %d, checkpoint %v; want seq 1 with uplink 10", a.ckpt.seq, loaded())
	}
	a.checkpointLocked()
	if a.ckpt.seq != 1 {
		t.Fatalf("idle tick wrote (seq %d)", a.ckpt.seq)
	}
	set(11)
	a.checkpointLocked()
	if a.ckpt.seq != 2 || uplinkOf(loaded()[0]) != 11 {
		t.Fatalf("seq %d, checkpoint %v; want seq 2 with uplink 11", a.ckpt.seq, loaded())
	}
	a.finals.add(&pb.TrafficReport{SessionId: "older", Users: []*pb.UserTraffic{{UserId: testUser, UpBytes: 7}}})
	a.checkpointLocked()
	if got := loaded(); a.ckpt.seq != 3 || len(got) != 2 || got[0].SessionId != "older" || got[1].SessionId != session {
		t.Fatalf("seq %d, checkpoint %v; want seq 3 with the final and the live report", a.ckpt.seq, got)
	}
	a.checkpointLocked()
	if a.ckpt.seq != 3 {
		t.Fatalf("idle tick wrote (seq %d)", a.ckpt.seq)
	}

	// A failed write is retried on the next tick although nothing changed
	// (the next slot is made a directory, which cannot be opened for
	// writing even as root).
	for i, f := range a.ckpt.files {
		if f != nil {
			_ = f.Close()
		}
		a.ckpt.files[i] = nil
	}
	next := a.ckpt.path(int((a.ckpt.seq + 1) % 2))
	if err := os.Remove(next); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(next, 0o700); err != nil {
		t.Fatal(err)
	}
	set(12)
	a.checkpointLocked()
	if !a.ckpt.dirty {
		t.Fatal("failed write did not leave the checkpoint dirty")
	}
	if err := os.Remove(next); err != nil {
		t.Fatal(err)
	}
	a.checkpointLocked()
	if got := loaded(); a.ckpt.dirty || len(got) != 2 || uplinkOf(got[1]) != 12 {
		t.Fatalf("dirty %v, checkpoint %v; want the retried write with uplink 12", a.ckpt.dirty, got)
	}

	// Teardown moves the counters into the final queue: the live report
	// leaves the checkpoint, the final one carries the values.
	a.finals.add(a.core.Teardown())
	a.checkpointLocked()
	if got := loaded(); len(got) != 2 || got[1].SessionId != session || uplinkOf(got[1]) != 12 {
		t.Fatalf("after teardown checkpoint %v; want the two finals only", got)
	}
}

func TestCheckpointRoundTripAndTornSlot(t *testing.T) {
	dir := t.TempDir()
	c := &checkpointStore{dir: dir}
	r1 := &pb.TrafficReport{SessionId: "s1", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 1, DownBytes: 2}}}
	r2 := &pb.TrafficReport{SessionId: "s1", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 3, DownBytes: 4}}}
	for _, r := range []*pb.TrafficReport{r1, r2} {
		if err := c.write(checkpointFrame(t, r)); err != nil {
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
	p := checkpointFrame(t, &pb.TrafficReport{SessionId: "s2", Users: []*pb.UserTraffic{{UserId: "u", UpBytes: 9}}})
	if err := n.write(p); err != nil {
		t.Fatal(err)
	}
	if got = (&checkpointStore{dir: dir}).load(); got[0].SessionId != "s2" {
		t.Fatalf("new write outranked by a leftover slot: %v", got)
	}
	if err := n.write(make([]byte, checkpointHdr+maxCheckpointPayload+1)); err == nil {
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
