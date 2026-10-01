package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"akari/agent/pb"
)

func finalReport(session string, up uint64) *pb.TrafficReport {
	return &pb.TrafficReport{SessionId: session, Users: []*pb.UserTraffic{{UserId: testUser, UpBytes: up}}}
}

// A24: a final report counts as delivered only after its stream survived
// longer than keepalive needs to notice a dead peer.
func TestFinalQueueConfirmWindowOutlastsKeepalive(t *testing.T) {
	if finalsConfirmAfter <= keepaliveTime+keepaliveTimeout {
		t.Fatalf("confirm window %v must exceed keepalive death time %v", finalsConfirmAfter, keepaliveTime+keepaliveTimeout)
	}
	var q finalQueue
	q.add(finalReport("s1", 1))
	_, send := collect()
	q.flush(7, send)
	// Another stream's tick never confirms it.
	q.confirm(8, 0)
	if q.len() != 1 {
		t.Fatal("confirmed by a different stream")
	}
	// Same stream, but not up long enough (the old 10 s traffic interval).
	q.confirm(7, finalsConfirmAfter)
	if q.len() != 1 {
		t.Fatal("confirmed inside the keepalive death window")
	}
	q.items[0].sentAt = time.Now().Add(-finalsConfirmAfter - time.Second)
	q.confirm(7, finalsConfirmAfter)
	if q.len() != 0 {
		t.Fatal("not confirmed after the stream stayed up")
	}
	// A report sent on a stream that then died is re-sent on the next one.
	q.add(finalReport("s2", 2))
	out, send2 := collect()
	q.flush(1, send2)
	q.flush(1, send2) // same stream: once
	q.flush(2, send2) // next stream: again
	if len(*out) != 2 {
		t.Fatalf("sends %d, want 2", len(*out))
	}
}

// A26/A28: reconnect backoff doubles to a cap and resets after a stream
// that stayed up (the timing excludes the wait).
func TestNextBackoff(t *testing.T) {
	base := time.Second
	d := base
	var seq []time.Duration
	for range 8 {
		d = nextBackoff(d, base, time.Second)
		seq = append(seq, d)
	}
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30, 30}
	for i, w := range want {
		if seq[i] != w*time.Second {
			t.Fatalf("step %d = %v, want %v", i, seq[i], w*time.Second)
		}
	}
	if got := nextBackoff(30*time.Second, base, stableStream+time.Second); got != base {
		t.Fatalf("reset = %v", got)
	}
	// A 30 s long session (the cap) is not stable: only > 1 min resets.
	if got := nextBackoff(4*time.Second, base, 30*time.Second); got != 8*time.Second {
		t.Fatalf("30 s stream reset the backoff: %v", got)
	}
}

// A25 (G2): the enrollment RPC succeeds but the result cannot be stored:
// permanent error naming the real cause, no retry with the spent token.
func TestEnrollStoreFailureIsPermanent(t *testing.T) {
	ca := newTestCA(t)
	ids, err := loadIdentities(t.TempDir(), &Config{Identity: IdentityConfig{CAPEM: ca.pem}})
	if err != nil {
		t.Fatal(err)
	}
	a := NewAgent(&Config{EnrollmentToken: "tok"}, "test", ids)
	a.backoffBase = 5 * time.Millisecond
	var calls atomic.Int32
	a.enrollRPC = func(context.Context, *pb.EnrollRequest) (*pb.IssuedCertificate, error) {
		calls.Add(1)
		return &pb.IssuedCertificate{CertPem: "not a certificate"}, nil
	}
	err = a.ensureEnrolled(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cannot be stored") || strings.Contains(err.Error(), "token is unknown") {
		t.Fatalf("want a store error, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("enrollment retried %d times with a spent token", calls.Load())
	}
}

// A25 (G5): a refused token with an existing identity is remembered, so a
// restart does not ask the panel again.
func TestRefusedTokenWithIdentityWritesMarker(t *testing.T) {
	ca := newTestCA(t)
	ids := ca.enrolledIDs(t)
	a := NewAgent(&Config{EnrollmentToken: "stale"}, "test", ids)
	var calls atomic.Int32
	a.enrollRPC = func(context.Context, *pb.EnrollRequest) (*pb.IssuedCertificate, error) {
		calls.Add(1)
		return nil, status.Error(codes.PermissionDenied, "token used")
	}
	if err := a.ensureEnrolled(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ids.dir, enrolledMarker))
	if err != nil || strings.TrimSpace(string(b)) != tokenDigest("stale") {
		t.Fatalf("marker %q %v", b, err)
	}
	if err := a.ensureEnrolled(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("second start asked the panel again: err=%v calls=%d", err, calls.Load())
	}
}
