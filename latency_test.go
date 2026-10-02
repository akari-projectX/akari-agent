package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"akari/agent/pb"
)

func TestSettingsFromClampsAndDefaults(t *testing.T) {
	s := settingsFrom(&pb.LatencyProbeConfig{})
	if s.interval != defaultProbeInterval || s.timeout != defaultProbeTimeout || s.attempts != 3 ||
		len(s.urls) != 2 || s.urls[0] != "https://www.gstatic.com/generate_204" ||
		s.urls[1] != "https://cp.cloudflare.com/generate_204" {
		t.Fatalf("defaults %+v", s)
	}
	s = settingsFrom(&pb.LatencyProbeConfig{
		IntervalSeconds: 1, TimeoutMs: 99999, Attempts: 9,
		Urls: []string{"ftp://x", "https://a.example/x", "https://a.example/x", "http://user:pw@b.example/", "http://c.example/204", "https://d/", "https://e/", "https://f/"},
	})
	if s.interval != minProbeInterval || s.timeout != maxProbeTimeout || s.attempts != maxProbeAttempts {
		t.Fatalf("clamp %+v", s)
	}
	want := []string{"https://a.example/x", "http://c.example/204", "https://d/", "https://e/"}
	if len(s.urls) != len(want) {
		t.Fatalf("urls %v", s.urls)
	}
	for i := range want {
		if s.urls[i] != want[i] {
			t.Fatalf("urls %v", s.urls)
		}
	}
	if s := settingsFrom(&pb.LatencyProbeConfig{IntervalSeconds: 1 << 31}); s.interval != maxProbeInterval {
		t.Fatalf("%v", s.interval)
	}
	if s := settingsFrom(&pb.LatencyProbeConfig{TimeoutMs: 1}); s.timeout != minProbeTimeout {
		t.Fatalf("%v", s.timeout)
	}
}

func TestMedian(t *testing.T) {
	ms := time.Millisecond
	if got := median([]time.Duration{30 * ms, 10 * ms, 20 * ms}); got != 20*ms {
		t.Fatal(got)
	}
	if got := median([]time.Duration{40 * ms, 10 * ms}); got != 25*ms {
		t.Fatal(got)
	}
	if got := median(nil); got != 0 {
		t.Fatal(got)
	}
}

// Real HTTP against a local server: a 204 counts, the delay covers the
// whole request, every attempt is a new connection.
func TestMeasureOnceLocal(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	p := newProber()
	r := p.measureURL(context.Background(), srv.URL+"/generate_204", 3, 2*time.Second)
	if !r.Ok || r.DelayMs < 20 || len(r.AttemptsMs) != 3 || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if n := conns.Load(); n != 3 {
		t.Fatalf("connections %d, want a fresh one per attempt", n)
	}
	// A redirect is an answer too (not followed).
	red := httptest.NewServer(http.RedirectHandler("http://192.0.2.1/", http.StatusFound))
	defer red.Close()
	if d, err := measureOnce(context.Background(), red.URL, time.Second); err != nil || d <= 0 {
		t.Fatalf("%v %v", d, err)
	}
}

func TestMeasureTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	start := time.Now()
	p := newProber()
	r := p.measureURL(context.Background(), srv.URL, 2, 150*time.Millisecond)
	if r.Ok || r.DelayMs != 0 || r.Error != "timeout" || len(r.AttemptsMs) != 2 || r.AttemptsMs[0] != 0 {
		t.Fatalf("%+v", r)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("timeouts not honoured: %v", el)
	}
}

// Fallback: the first URL fails, the second answers and ends the run;
// a failed attempt counts as the timeout in the median.
func TestRunFallbackAndMedian(t *testing.T) {
	p := newProber()
	var mu sync.Mutex
	calls := map[string]int{}
	p.measure = func(_ context.Context, u string, timeout time.Duration) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[u]++
		switch u {
		case "https://a/":
			return 0, errors.New("dial tcp: connection refused")
		case "https://b/":
			if calls[u] == 2 {
				return 0, context.DeadlineExceeded
			}
			return 40 * time.Millisecond, nil
		}
		t.Fatalf("unexpected url %s", u)
		return 0, nil
	}
	set := probeSettings{interval: time.Hour, timeout: time.Second, attempts: 3, urls: []string{"https://a/", "https://b/", "https://c/"}}
	rep := p.run(context.Background(), set)
	if len(rep.Results) != 2 || rep.Results[0].Ok || rep.Results[0].Error == "" || !rep.Results[1].Ok {
		t.Fatalf("%+v", rep.Results)
	}
	// attempts 40, timeout(1000), 40 -> median 40.
	if b := rep.Results[1]; b.DelayMs != 40 || b.AttemptsMs[1] != 0 {
		t.Fatalf("%+v", b)
	}
	if rep.MeasuredAtUnix == 0 {
		t.Fatal("no timestamp")
	}
}

// Scheduling: a run soon after start, "test now" on a new token (but not
// for the first token seen), coalescing within minProbeGap.
func TestProberLoopTokens(t *testing.T) {
	p := newProber()
	p.jitter = func() float64 { return 0 } // first run immediately
	var runs atomic.Int32
	p.measure = func(context.Context, string, time.Duration) (time.Duration, error) {
		runs.Add(1)
		return 5 * time.Millisecond, nil
	}
	got := make(chan *pb.LatencyReport, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.configure(&pb.LatencyProbeConfig{RunToken: 7, Attempts: 1, IntervalSeconds: 3600})
	go p.loop(ctx, func(r *pb.LatencyReport) { got <- r })
	first := <-got
	if first.RunToken != 0 || len(first.Results) != 1 || !first.Results[0].Ok {
		t.Fatalf("startup run %+v", first)
	}
	if p.latestReport() != first {
		t.Fatal("latest not kept")
	}
	// Same token again: nothing.
	p.configure(&pb.LatencyProbeConfig{RunToken: 7, Attempts: 1, IntervalSeconds: 3600})
	select {
	case r := <-got:
		t.Fatalf("unexpected run %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	// A new token right after a run is coalesced to minProbeGap; pretend
	// the last run was long ago so it runs at once.
	p.mu.Lock()
	p.lastRun = time.Now().Add(-time.Minute)
	p.mu.Unlock()
	p.configure(&pb.LatencyProbeConfig{RunToken: 8, Attempts: 1, IntervalSeconds: 3600})
	select {
	case r := <-got:
		if r.RunToken != 8 {
			t.Fatalf("token %d", r.RunToken)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("requested run did not happen")
	}
	// Immediately again: coalesced, not run within the gap.
	p.configure(&pb.LatencyProbeConfig{RunToken: 9, Attempts: 1, IntervalSeconds: 3600})
	select {
	case r := <-got:
		t.Fatalf("run inside the gap %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
}

// A settings change (new interval) while a "test now" is coalesced must
// not push the requested run out to the new interval (W12 smoke finding:
// 系统设置 change + 立即测速 within minProbeGap of the last run).
func TestProberCoalescedRequestSurvivesReschedule(t *testing.T) {
	p := newProber()
	p.measure = func(context.Context, string, time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	}
	got := make(chan *pb.LatencyReport, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.configure(&pb.LatencyProbeConfig{RunToken: 1, Attempts: 1, IntervalSeconds: 3600})
	// The last run was just under minProbeGap ago (no startup run pending:
	// the loop's first deadline is far away).
	p.jitter = func() float64 { return 0.5 }
	p.mu.Lock()
	p.lastRun = time.Now().Add(-minProbeGap + 400*time.Millisecond)
	p.mu.Unlock()
	go p.loop(ctx, func(r *pb.LatencyReport) { got <- r })
	time.Sleep(50 * time.Millisecond)
	p.configure(&pb.LatencyProbeConfig{RunToken: 2, Attempts: 1, IntervalSeconds: 3600})
	time.Sleep(50 * time.Millisecond) // the loop coalesced the request
	p.configure(&pb.LatencyProbeConfig{RunToken: 2, Attempts: 1, IntervalSeconds: 1200})
	select {
	case r := <-got:
		if r.RunToken != 2 {
			t.Fatalf("token %d", r.RunToken)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the coalesced request was lost by the reschedule")
	}
}

// The Hello advertises the W11 capabilities; a LatencyProbeConfig is taken
// by handleDown without an Ack or any state change.
func TestAgentLatencyCapabilityAndConfig(t *testing.T) {
	a := NewAgent(&Config{}, "test", nil)
	h := a.helloLocked().GetHello()
	if len(h.Capabilities) != 3 || h.Capabilities[0] != "metrics" || h.Capabilities[1] != "latency" ||
		h.Capabilities[2] != "updater" {
		t.Fatalf("capabilities %v", h.Capabilities)
	}
	out, send := collect()
	msg := &pb.PanelDown{Msg: &pb.PanelDown_LatencyProbe{LatencyProbe: &pb.LatencyProbeConfig{
		IntervalSeconds: 7200, Urls: []string{"https://probe.example/204"}, RunToken: 3}}}
	if err := a.handleDown(context.Background(), 0, send, msg); err != nil {
		t.Fatal(err)
	}
	if len(*out) != 0 {
		t.Fatalf("unexpected reply %v", *out)
	}
	a.prober.mu.Lock()
	defer a.prober.mu.Unlock()
	if a.prober.set.interval != 2*time.Hour || a.prober.set.urls[0] != "https://probe.example/204" || a.prober.token != 3 {
		t.Fatalf("%+v", a.prober.set)
	}
}
