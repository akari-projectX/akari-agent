package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
)

// stalledPanel: a fake panel that keeps the connection alive (HTTP/2 and
// keepalive answered by the transport) but, after the first Snapshot's Ack,
// stops reading stream 1 and pushes a second Snapshot. The agent's queue
// fills (heartbeats every millisecond), so the reader applying that
// Snapshot blocks in send while holding applyMu (C2). Later streams are
// drained normally. The stream window is fixed at 64 KiB so unread data
// back-pressures the agent quickly.
type stalledPanel struct {
	addr string
	// applying: the second Snapshot was sent while the queue is full.
	applying chan struct{}
	inb      string
}

func startStalledPanel(t *testing.T) *stalledPanel {
	inb, users := testSnapshot(freePort(t))
	p := &stalledPanel{applying: make(chan struct{}), inb: inb}
	f := &fakePanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		if n > 1 {
			for {
				if _, err := s.Recv(); err != nil {
					return nil
				}
			}
		}
		recvHello(t, s)
		_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 3600}}})
		_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
			ConfigVersion: 1, UserVersion: 1, InboundsJson: inb, Users: users}}})
		for {
			m, err := s.Recv()
			if err != nil {
				return nil
			}
			if _, ok := m.Msg.(*pb.AgentUp_Ack); ok {
				break
			}
		}
		// Stop reading. Give the heartbeats time to fill the stream
		// window and the queue, then push work that sends under applyMu.
		time.Sleep(1500 * time.Millisecond)
		_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
			ConfigVersion: 2, UserVersion: 2, InboundsJson: inb, Users: users}}})
		close(p.applying)
		<-s.Context().Done()
		return nil
	}
	p.addr = startFakePanel(t, f, grpc.InitialWindowSize(1<<16), grpc.InitialConnWindowSize(1<<16))
	return p
}

// stallAgent: an agent against p whose queue fills fast and whose stall
// bound is short but long enough for the reader to be stuck under applyMu
// when the test acts.
func stallAgent(t *testing.T, p *stalledPanel) (*Agent, *atomic.Int64) {
	a := testAgent(t, p.addr)
	a.heartbeatEvery = time.Millisecond
	a.trafficEvery = time.Hour
	a.sendStall = 5 * time.Second
	a.shutdownFlush = time.Second
	a.finalsStore = &finalsStore{dir: t.TempDir()}
	clock := new(atomic.Int64)
	a.lease = newLeaseState(func() time.Duration { return time.Duration(clock.Load()) })
	a.leaseEvery = time.Hour // the test calls checkLease itself
	return a, clock
}

// C2: the panel stops reading while the reader holds applyMu in send. The
// lease must still be able to tear xray down (bounded by sendStall), and
// the stream is closed and re-dialed.
func TestStalledPanelLeaseStillTearsDown(t *testing.T) {
	p := startStalledPanel(t)
	a, clock := stallAgent(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }()

	select {
	case <-p.applying:
	case <-time.After(20 * time.Second):
		t.Fatal("second snapshot never pushed")
	}
	time.Sleep(200 * time.Millisecond) // the reader is inside handleDown now
	if !a.core.Running() {
		t.Fatal("xray not running before the lease runs out")
	}
	a.core.mu.Lock() // the reader is blocked in send, not in the core
	session := a.core.sessionID
	stamp(a.core.instance, 777)
	a.core.mu.Unlock()
	clock.Store(int64(2 * time.Hour)) // past the 1h lease
	start := time.Now()
	done := make(chan struct{})
	go func() { a.checkLease(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second): // sendStall (5s) + margin
		t.Fatal("lease expiry could not take applyMu: a send held it past sendStall")
	}
	if a.core.Running() {
		t.Fatal("lease expired but xray still runs")
	}
	t.Logf("lease teardown took %v (sendStall %v)", time.Since(start), a.sendStall)
	var queued bool
	for _, r := range a.finals.all() {
		queued = queued || (r.SessionId == session && uplinkOf(r) == 777)
	}
	if !queued {
		t.Fatal("torn-down instance's counters were not queued")
	}
}

// C2: SIGTERM while the panel does not read and the reader holds applyMu:
// the stop completes well within systemd's TimeoutStopSec (20 s) — a
// waiting send gets shutdownFlush more, not sendStall — and the final
// counters are persisted for the next process.
func TestStalledPanelGracefulStopCompletes(t *testing.T) {
	p := startStalledPanel(t)
	a, _ := stallAgent(t, p)
	var session1 string
	stamped := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }()

	// Stamp the first instance's counters as soon as it runs.
	go func() {
		defer close(stamped)
		for !a.core.Running() {
			time.Sleep(time.Millisecond)
		}
		a.core.mu.Lock()
		session1 = a.core.sessionID
		stamp(a.core.instance, 4242)
		a.core.mu.Unlock()
	}()
	<-stamped
	select {
	case <-p.applying:
	case <-time.After(20 * time.Second):
		t.Fatal("second snapshot never pushed")
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel() // SIGTERM
	select {
	case <-runDone:
	case <-time.After(a.sendStall):
		t.Fatal("graceful stop did not complete: a stalled send kept applyMu")
	}
	took := time.Since(start)
	t.Logf("graceful stop took %v (shutdownFlush %v, sendStall %v)", took, a.shutdownFlush, a.sendStall)
	if took > a.shutdownFlush+3*time.Second {
		t.Fatalf("graceful stop took %v, want about shutdownFlush", took)
	}
	if a.core.Running() {
		t.Fatal("xray still running after the stop")
	}
	var found bool
	for _, r := range a.finalsStore.load() {
		if r.SessionId == session1 && uplinkOf(r) == 4242 {
			found = true
		}
	}
	if !found {
		t.Fatalf("first instance's final counters (session %s) not persisted: %v", session1, a.finalsStore.load())
	}
}

// C3: a Snapshot larger than grpc-go's 4 MiB default is received and
// applied (it used to end the stream with ResourceExhausted, every time).
func TestLargeSnapshotIsReceived(t *testing.T) {
	port := freePort(t)
	inb := fmt.Sprintf(`[{"tag":"in","listen":"127.0.0.1","port":%d,"protocol":"vless",`+
		`"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}}]`, port)
	const n = 40_000 // ~110 B per user on one inbound
	users := make([]*pb.UserOp, n)
	for i := range users {
		users[i] = &pb.UserOp{Op: pb.UserOp_ADD, UserId: benchUserID(i), InboundUsers: []*pb.InboundUser{{
			InboundTag: "in", Protocol: "vless",
			AccountJson: fmt.Sprintf(`{"flow":"","id":"%08d-0000-4000-8000-%012d"}`, i, i),
		}}}
	}
	snap := &pb.ConfigSnapshot{ConfigVersion: 7, UserVersion: 7, InboundsJson: inb, Users: users}
	if size := proto.Size(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: snap}}); size <= 4<<20 {
		t.Fatalf("snapshot is only %d bytes; the test needs > 4 MiB", size)
	}
	acks := make(chan *pb.Ack, 1)
	f := &fakePanel{}
	f.onStream = func(_ int32, s pb.AgentChannel_OpenChannelServer) error {
		recvHello(t, s)
		_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: snap}})
		for {
			m, err := s.Recv()
			if err != nil {
				return nil
			}
			if x, ok := m.Msg.(*pb.AgentUp_Ack); ok {
				acks <- x.Ack
				<-s.Context().Done()
				return nil
			}
		}
	}
	a := testAgent(t, startFakePanel(t, f))
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()
	defer func() { cancel(); <-runDone }()
	select {
	case ack := <-acks:
		if !ack.Ok || ack.ConfigVersion != 7 {
			t.Fatalf("ack %v", ack)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("no ack for a > 4 MiB snapshot (streams opened: %d)", f.streams.Load())
	}
	if got := a.core.UserCount(); got != n {
		t.Fatalf("%d users applied, want %d", got, n)
	}
	if f.streams.Load() != 1 {
		t.Fatalf("stream re-dialed %d times", f.streams.Load()-1)
	}
}

// W6: full jitter stays within [0, d) and actually spreads.
func TestFullJitter(t *testing.T) {
	if fullJitter(0) != 0 || fullJitter(-time.Second) != 0 {
		t.Fatal("non-positive backoff must not wait")
	}
	seen := map[time.Duration]bool{}
	for range 1000 {
		w := fullJitter(time.Second)
		if w < 0 || w >= time.Second {
			t.Fatalf("jitter %v out of [0, 1s)", w)
		}
		seen[w/(100*time.Millisecond)] = true
	}
	if len(seen) < 8 {
		t.Fatalf("jitter does not spread: %d of 10 deciles hit", len(seen))
	}
}
