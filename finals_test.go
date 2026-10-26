package main

import (
	"fmt"
	"testing"
	"time"

	"akari/agent/pb"
)

func upOf(r *pb.TrafficReport, user string) (up, down uint64, ok bool) {
	for _, u := range r.Users {
		if u.UserId == user {
			return u.UpBytes, u.DownBytes, true
		}
	}
	return 0, 0, false
}

// P3-3: reports of one session (a removed user's final counters, then the
// instance's) are one item: cumulative values, the larger one per user.
func TestFinalQueueMergesReportsOfOneSession(t *testing.T) {
	var q finalQueue
	first := &pb.TrafficReport{SessionId: "s1", MonotonicMs: 5, Users: []*pb.UserTraffic{
		{UserId: "a", UpBytes: 10, DownBytes: 100}, {UserId: "b", UpBytes: 7}}}
	q.add(first)
	out, send := collect()
	q.flush(1, send)
	q.add(&pb.TrafficReport{SessionId: "s1", MonotonicMs: 9, Users: []*pb.UserTraffic{
		{UserId: "a", UpBytes: 12, DownBytes: 90}, {UserId: "c", DownBytes: 3}}})
	q.add(&pb.TrafficReport{SessionId: "s2", Users: []*pb.UserTraffic{{UserId: "a", UpBytes: 1}}})
	if q.len() != 2 {
		t.Fatalf("queue length = %d, want 2 (one per session)", q.len())
	}
	merged := q.all()[0]
	for _, tc := range []struct {
		user     string
		up, down uint64
	}{{"a", 12, 100}, {"b", 7, 0}, {"c", 0, 3}} {
		up, down, ok := upOf(merged, tc.user)
		if !ok || up != tc.up || down != tc.down {
			t.Errorf("merged %s = %d/%d (present %v), want %d/%d", tc.user, up, down, ok, tc.up, tc.down)
		}
	}
	if merged.MonotonicMs != 9 {
		t.Errorf("MonotonicMs = %d, want 9", merged.MonotonicMs)
	}
	if up, _, _ := upOf(first, "a"); up != 10 {
		t.Errorf("the first report was modified: a.up = %d, want 10", up)
	}
	// The merged session was already sent on this stream: it goes out again.
	*out = nil
	q.flush(1, send)
	if len(*out) != 2 {
		t.Errorf("sends after the merge = %d, want 2 (merged s1 and new s2)", len(*out))
	}
}

// P3-3: the panel keeps at most 16 unpersisted sessions per server (flush
// every 5 s) and drops the report of any further new session. Whatever the
// backlog, the agent never puts more than finalsPerBurst sessions into one
// panel flush interval.
func TestFinalQueueBurstsStayWithinThePanelsAdmission(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	q := finalQueue{now: func() time.Time { return now }}
	const sessions = 40
	for i := range sessions {
		q.add(finalReport(fmt.Sprintf("s%02d", i), uint64(i+1)))
	}
	delivered := map[string]bool{}
	var window = map[string]bool{} // sessions seen in the current 5 s panel flush window
	windowStart := now
	var send = func(m *pb.AgentUp) error {
		s := m.GetTraffic().GetSessionId()
		if now.Sub(windowStart) >= 5*time.Second {
			window, windowStart = map[string]bool{}, now
		}
		window[s] = true
		delivered[s] = true
		if len(window) > finalsPerBurst {
			t.Fatalf("%d sessions within one panel flush window at %v, want at most %d", len(window), now, finalsPerBurst)
		}
		return nil
	}
	// The traffic tick (every 10 s, as in production, or every second).
	for range 200 {
		q.flush(1, send)
		now = now.Add(time.Second)
	}
	if len(delivered) != sessions {
		t.Errorf("delivered %d sessions, want %d", len(delivered), sessions)
	}
	// A short queue is never delayed.
	q2 := finalQueue{now: func() time.Time { return now }}
	q2.add(finalReport("only", 1))
	out, send2 := collect()
	q2.flush(1, send2)
	q2.add(finalReport("next", 1))
	q2.flush(1, send2)
	if len(*out) != 2 {
		t.Errorf("a queue within one burst was delayed: %d sends, want 2", len(*out))
	}
}
