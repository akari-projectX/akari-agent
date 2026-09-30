package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"akari/agent/pb"
)

// Shared vectors with the panel (proto/state_hash_vectors.json).
func TestStateHashVectors(t *testing.T) {
	raw, err := os.ReadFile("proto/state_hash_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name          string `json:"name"`
			ConfigVersion uint64 `json:"config_version"`
			Users         []struct {
				UserID       string `json:"user_id"`
				InboundUsers []struct {
					InboundTag  string `json:"inbound_tag"`
					Protocol    string `json:"protocol"`
					AccountJSON string `json:"account_json"`
				} `json:"inbound_users"`
			} `json:"users"`
			Hash string `json:"hash"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 5 {
		t.Fatal("fixture has too few cases")
	}
	for _, c := range f.Cases {
		// Same collapsing rules as applyOpLocked: later tag entry wins.
		recs := map[[2]string]hashRecord{}
		for _, u := range c.Users {
			for _, iu := range u.InboundUsers {
				recs[[2]string{u.UserID, iu.InboundTag}] = hashRecord{u.UserID, iu.InboundTag, iu.Protocol, iu.AccountJSON}
			}
		}
		var list []hashRecord
		for _, r := range recs {
			list = append(list, r)
		}
		if got := stateHash(c.ConfigVersion, list); got != c.Hash {
			t.Errorf("%s: got %s want %s", c.Name, got, c.Hash)
		}
	}
}

// fakePanel is an in-process AgentChannel server; each stream runs onStream.
type fakePanel struct {
	pb.UnimplementedAgentChannelServer
	streams  atomic.Int32
	onStream func(n int32, s pb.AgentChannel_OpenChannelServer) error
}

func (f *fakePanel) OpenChannel(s pb.AgentChannel_OpenChannelServer) error {
	return f.onStream(f.streams.Add(1), s)
}

func startFakePanel(t *testing.T, f *fakePanel) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterAgentChannelServer(srv, f)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return l.Addr().String()
}

func testAgent(t *testing.T, addr string) *Agent {
	a := NewAgent(&Config{PanelAddr: addr}, "test")
	a.backoffBase = 10 * time.Millisecond
	a.dial = func(ctx context.Context) (pb.AgentChannel_OpenChannelClient, func(), error) {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, func() {}, err
		}
		s, err := pb.NewAgentChannelClient(conn).OpenChannel(ctx)
		if err != nil {
			_ = conn.Close()
			return nil, func() {}, err
		}
		return s, func() { _ = conn.Close() }, nil
	}
	t.Cleanup(func() { a.core.Teardown() })
	return a
}

func recvHello(t *testing.T, s pb.AgentChannel_OpenChannelServer) *pb.Hello {
	t.Helper()
	for {
		m, err := s.Recv()
		if err != nil {
			t.Errorf("recv: %v", err)
			return nil
		}
		if h, ok := m.Msg.(*pb.AgentUp_Hello); ok {
			return h.Hello
		}
	}
}

// F3: the stream dies (writer error) while the reader is inside a Rebuild.
// The next stream must not start until that reader is done, and the dead
// stream's snapshot must not move the held versions or send anything.
func TestNextStreamWaitsForDeadStreamsReader(t *testing.T) {
	inb, users := testSnapshot(freePort(t))
	inRebuild := make(chan struct{})
	release := make(chan struct{})
	var active, maxActive atomic.Int32
	stream1Closed := make(chan struct{})
	helloOnStream2 := make(chan *pb.Hello, 1)
	var stream1Msgs []*pb.AgentUp
	var mu sync.Mutex

	f := &fakePanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		switch n {
		case 1:
			recvHello(t, s)
			_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
				ConfigVersion: 2, UserVersion: 2, InboundsJson: inb, Users: users}}})
			<-inRebuild
			// Drain whatever else arrives briefly, then kill the stream.
			go func() {
				for {
					m, err := s.Recv()
					if err != nil {
						return
					}
					mu.Lock()
					stream1Msgs = append(stream1Msgs, m)
					mu.Unlock()
				}
			}()
			close(stream1Closed)
			return nil
		default:
			helloOnStream2 <- recvHello(t, s)
			<-s.Context().Done()
			return nil
		}
	}
	addr := startFakePanel(t, f)
	a := testAgent(t, addr)
	a.heartbeatEvery = 20 * time.Millisecond // makes the writer hit the dead stream
	var once sync.Once
	a.core.onStart = func(*core.Instance) {
		if active.Add(1) > maxActive.Load() {
			maxActive.Store(active.Load())
		}
		once.Do(func() {
			close(inRebuild)
			<-release
		})
		active.Add(-1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() { _ = a.Run(ctx); close(runDone) }()

	<-stream1Closed
	time.Sleep(500 * time.Millisecond) // heartbeats fail on the dead stream meanwhile
	n := f.streams.Load()
	close(release)
	if n != 1 {
		cancel()
		<-runDone
		t.Fatalf("a new stream (%d) started while the old reader was still in Rebuild", n)
	}
	var h *pb.Hello
	select {
	case h = <-helloOnStream2:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not reconnect")
	}
	if h.ConfigVersion != 0 || h.UserVersion != 0 {
		t.Fatalf("dead stream's snapshot moved held versions: hello %d/%d", h.ConfigVersion, h.UserVersion)
	}
	if !a.isDirty() {
		t.Fatal("state applied after its stream died must be dirty")
	}
	mu.Lock()
	for _, m := range stream1Msgs {
		if _, ok := m.Msg.(*pb.AgentUp_Ack); ok {
			t.Fatal("dead stream got an ack")
		}
	}
	mu.Unlock()
	if maxActive.Load() > 1 {
		t.Fatal("two applies ran concurrently")
	}
	cancel()
	<-runDone
}

// Lease: expiry tears xray down, keeps the final counters for the next
// stream (old session), resets held versions so the next Hello is (0,0).
// Grants from a stale stream are ignored; pushed values are clamped.
func TestLeaseExpiryTeardownAndReport(t *testing.T) {
	var clock atomic.Int64
	now := func() time.Duration { return time.Duration(clock.Load()) }

	inb, users := testSnapshot(freePort(t))
	hellos := make(chan *pb.Hello, 4)
	traffic := make(chan *pb.TrafficReport, 16)
	granted := make(chan struct{})
	f := &fakePanel{}
	f.onStream = func(n int32, s pb.AgentChannel_OpenChannelServer) error {
		if n == 1 {
			recvHello(t, s)
			_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 60}}})
			_ = s.Send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: &pb.ConfigSnapshot{
				ConfigVersion: 3, UserVersion: 4, InboundsJson: inb, Users: users}}})
			for {
				m, err := s.Recv()
				if err != nil {
					return nil
				}
				if _, ok := m.Msg.(*pb.AgentUp_Ack); ok {
					close(granted)
					return nil // panel goes away
				}
			}
		}
		for {
			m, err := s.Recv()
			if err != nil {
				return nil
			}
			switch x := m.Msg.(type) {
			case *pb.AgentUp_Hello:
				hellos <- x.Hello
			case *pb.AgentUp_Traffic:
				traffic <- x.Traffic
			}
		}
	}
	addr := startFakePanel(t, f)
	a := testAgent(t, addr)
	a.lease = newLeaseState(now)
	a.backoffBase = 300 * time.Millisecond // leave time to expire offline

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-granted
	left, armed := a.lease.remaining()
	if !armed || left != time.Hour {
		t.Fatalf("60s grant must clamp to the 1h floor, got %v armed=%v", left, armed)
	}
	oldSession := a.core.SessionID()
	a.core.mu.Lock()
	stamp(a.core.instance, 999)
	a.core.mu.Unlock()

	// Offline now. Not yet expired: nothing happens.
	clock.Store(int64(59 * time.Minute))
	a.checkLease()
	if !a.core.Running() {
		t.Fatal("torn down before expiry")
	}
	clock.Store(int64(time.Hour))
	a.checkLease()
	if a.core.Running() {
		t.Fatal("xray still running after lease expiry")
	}
	if c, u := a.versions(); c != 0 || u != 0 {
		t.Fatalf("held versions after expiry = %d/%d", c, u)
	}

	// Reconnect: Hello (0,0), then the final counters under the old session.
	var h *pb.Hello
	for h == nil || h.ConfigVersion != 0 {
		select {
		case h = <-hellos:
		case <-time.After(5 * time.Second):
			t.Fatal("no hello after reconnect")
		}
	}
	if h.UserVersion != 0 || h.StateHash != stateHash(0, nil) {
		t.Fatalf("hello after expiry = %v", h)
	}
	select {
	case r := <-traffic:
		if r.SessionId != oldSession || uplinkOf(r) != 999 {
			t.Fatalf("final report = %v, want session %s", r, oldSession)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("final counters not reported after reconnect")
	}

	// A grant from a stale stream generation is ignored.
	cur, _ := a.current()
	_ = a.handleDown(ctx, cur+100, func(*pb.AgentUp) error { return nil },
		&pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 7200}}})
	if left, _ := a.lease.remaining(); left != 0 {
		t.Fatal("stale stream's grant renewed the lease")
	}
	cancel()
}

func TestLeaseClampAndWarnings(t *testing.T) {
	for _, c := range []struct {
		in   uint64
		want time.Duration
	}{
		{0, 24 * time.Hour}, {1, time.Hour}, {3599, time.Hour}, {7200, 2 * time.Hour},
		{1 << 62, maxLease},
	} {
		if got := clampLease(c.in); got != c.want {
			t.Errorf("clamp(%d) = %v, want %v", c.in, got, c.want)
		}
	}
	var clock time.Duration
	l := newLeaseState(func() time.Duration { return clock })
	if l.check() {
		t.Fatal("unarmed lease never expires")
	}
	l.grant(0)
	clock = 12 * time.Hour
	if l.check() || l.warned != 50 {
		t.Fatalf("50%% warning: warned=%d", l.warned)
	}
	clock = 22 * time.Hour
	if l.check() || l.warned != 90 {
		t.Fatalf("90%% warning: warned=%d", l.warned)
	}
	clock = 24 * time.Hour
	if !l.check() {
		t.Fatal("expired lease not reported")
	}
	l.grant(7200)
	if l.check() || l.warned != 0 {
		t.Fatal("a new grant renews the lease")
	}
}
