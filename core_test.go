package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"

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

func stamp(inst *core.Instance, v int64) {
	sm := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	name := "user>>>" + testUser + ">>>traffic>>>uplink"
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
