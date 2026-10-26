package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"akari/agent/pb"
)

func (m *CoreManager) sizes() (counted, gone, issued, stale int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, users := range m.issued {
		issued += len(users)
	}
	return len(m.counted), len(m.goneCounters), issued, len(m.staleIssued)
}

// P3-4: counted and issued must not grow with user churn on a long-lived
// instance, and nothing billable or revivable may be lost on the way.
func TestSweepGoneBoundsChurn(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	clock := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	echo := echoServer(t)
	p := freePort(t)
	if _, err := m.Rebuild(twoInbounds(p, freePort(t)), []*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	// userA carries real traffic; the churn users come and go.
	c, err := vlessDial(p, idA, echo)
	mustEcho(t, c, err, "traffic of A")
	c.Close()
	const churn = 300
	var adds, removes []*pb.UserOp
	for i := range churn {
		uid := fmt.Sprintf("cccccccc-0000-0000-0000-%012d", i)
		id := fmt.Sprintf("0c0c0c0c-1111-4111-8111-%012d", i)
		adds = append(adds, vlessUser(uid, "in-a", id))
		removes = append(removes, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: uid})
	}
	if _, err := m.ApplyUserOps(append(adds, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: userA})); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyUserOps(removes); err != nil {
		t.Fatal(err)
	}
	counted, gone, issued, stale := m.sizes()
	if counted != churn+1 || gone != churn+1 || issued != churn+1 || stale != churn+1 {
		t.Fatalf("after the churn counted/gone/issued/stale = %d/%d/%d/%d, want %d each", counted, gone, issued, stale, churn+1)
	}

	// Inside the grace period nothing is dropped (in-flight bytes of the
	// cut connections are still counted into these counters).
	clock = clock.Add(goneCounterGrace - time.Second)
	if r := m.SweepGone(); r != nil {
		t.Fatalf("SweepGone() inside the grace period = %v, want nil", r)
	}
	// A user re-added inside the grace period is not dropped later.
	if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second)
	r := m.SweepGone()
	counted, gone, issued, stale = m.sizes()
	if counted != 1 || gone != 0 || issued != churn+1 || stale != churn {
		t.Fatalf("after the grace period counted/gone/issued/stale = %d/%d/%d/%d, want 1/0/%d/%d", counted, gone, issued, stale, churn+1, churn)
	}
	if r != nil {
		t.Errorf("SweepGone() reported %v; the re-added user is live and the churn users had no traffic", r)
	}

	// A removed user with traffic: its cumulative value is handed over once.
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: userA}}); err != nil {
		t.Fatal(err)
	}
	want := uint64(0)
	for _, u := range m.TrafficSnapshot().GetUsers() {
		if u.UserId == userA {
			want = u.UpBytes
		}
	}
	if want == 0 {
		t.Fatal("no traffic counted for the user")
	}
	clock = clock.Add(goneCounterGrace)
	r = m.SweepGone()
	if r == nil || len(r.Users) != 1 || r.Users[0].UserId != userA || r.Users[0].UpBytes != want || r.SessionId != m.SessionID() {
		t.Fatalf("SweepGone() = %v, want one row for %s with up %d in this session", r, userA, want)
	}
	if counted, _, _, _ = m.sizes(); counted != 0 {
		t.Errorf("counted = %d after the sweep, want 0", counted)
	}

	// Credentials of removed users are kept for revival until the TTL.
	if _, _, issued, _ = m.sizes(); issued != churn+1 {
		t.Fatalf("issued = %d before the TTL, want %d", issued, churn+1)
	}
	clock = clock.Add(staleIssuedTTL)
	m.SweepGone()
	if _, _, issued, stale = m.sizes(); issued != 0 || stale != 0 {
		t.Errorf("after the TTL issued/stale = %d/%d, want 0/0", issued, stale)
	}

	// The counters xray kept continue on a re-add (not restarted from 0),
	// the user connects, and the new bytes are reported on top.
	if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(userA, "in-a", idA)}); err != nil {
		t.Fatal(err)
	}
	c, err = vlessDial(p, idA, echo)
	mustEcho(t, c, err, "A is back")
	c.Close()
	var got uint64
	for _, u := range m.TrafficSnapshot().GetUsers() {
		if u.UserId == userA {
			got = u.UpBytes
		}
	}
	if got <= want {
		t.Errorf("up after the re-add = %d, want more than %d", got, want)
	}
}

// Tombstones of Shadowsocks 2022 tags stay in xray's table and in issued
// whatever the age; only counters follow the general rule.
func TestSweepGoneKeepsTombstones(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	clock := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	inb := "[" + ssInbound("ss", freePort(t), "2022-blake3-aes-128-gcm", b64key(16, 1), true) + "]"
	op := ssOp("user-00", "ss", b64key(16, 10))
	if _, err := m.Rebuild(inb, []*pb.UserOp{op, ssOp("user-01", "ss", b64key(16, 11))}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: "user-00"}}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(staleIssuedTTL + time.Hour)
	m.SweepGone()
	if n := m.Tombstones("ss"); n != 1 {
		t.Fatalf("Tombstones() = %d, want 1", n)
	}
	if _, _, issued, stale := m.sizes(); issued != 2 || stale != 0 {
		t.Fatalf("issued/stale = %d/%d, want 2/0 (the tombstone's credential is kept)", issued, stale)
	}
	// Reviving the tombstone still works after the sweep.
	if _, err := m.ApplyUserOps([]*pb.UserOp{op}); err != nil {
		t.Fatalf("reviving the tombstone: %v", err)
	}
	if n := m.Tombstones("ss"); n != 0 {
		t.Errorf("Tombstones() after the revival = %d, want 0", n)
	}
}

// SweepGone runs on the traffic tick while deltas and reports run on other
// goroutines.
func TestSweepGoneRace(t *testing.T) {
	m := NewCoreManager()
	defer m.Teardown()
	var cm sync.Mutex
	clock := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { cm.Lock(); defer cm.Unlock(); clock = clock.Add(time.Minute); return clock }
	if _, err := m.Rebuild(twoInbounds(freePort(t), freePort(t)), nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 60 {
			uid := fmt.Sprintf("dddddddd-0000-0000-0000-%012d", i%7)
			id := fmt.Sprintf("0d0d0d0d-1111-4111-8111-%012d", i%7)
			if _, err := m.ApplyUserOps([]*pb.UserOp{vlessUser(uid, "in-a", id)}); err != nil {
				t.Error(err)
				return
			}
			if _, err := m.ApplyUserOps([]*pb.UserOp{{Op: pb.UserOp_REMOVE, UserId: uid}}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			m.SweepGone()
			m.TrafficChanges()
		}
	}()
	wg.Wait()
}
