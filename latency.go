package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"akari/agent/pb"
)

// Latency test (W11, capability "latency"; see LatencyProbeConfig in
// agent.proto): Clash-style url-test from the node's own egress. Each
// attempt is a fresh connection (no keep-alive, no proxy from the
// environment): delay = request start until the response headers, i.e.
// DNS + TCP connect + TLS + first byte. A run tries the URLs in order and
// stops at the first that answers; per URL the result is the median of
// its attempts, a failed attempt counting as the timeout.

const (
	defaultProbeInterval = 5 * time.Hour
	minProbeInterval     = 10 * time.Minute
	maxProbeInterval     = 7 * 24 * time.Hour
	defaultProbeTimeout  = 5 * time.Second
	minProbeTimeout      = time.Second
	maxProbeTimeout      = 30 * time.Second
	defaultProbeAttempts = 3
	maxProbeAttempts     = 5
	maxProbeURLs         = 4
	maxProbeURLLen       = 512
	// minProbeGap: "test now" requests closer than this are coalesced.
	minProbeGap = 10 * time.Second
	// The first scheduled run after the process starts happens within
	// this long (spread, so a fleet restart does not test all at once).
	startupProbeDelay = time.Minute
	// errMaxLen bounds UrlLatency.error.
	errMaxLen = 120
)

var defaultProbeURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

type probeSettings struct {
	interval time.Duration
	timeout  time.Duration
	attempts int
	urls     []string
}

func defaultProbeSettings() probeSettings {
	return probeSettings{
		interval: defaultProbeInterval,
		timeout:  defaultProbeTimeout,
		attempts: defaultProbeAttempts,
		urls:     slices.Clone(defaultProbeURLs),
	}
}

// validProbeURL: absolute http(s) URL with a host, bounded length.
func validProbeURL(s string) bool {
	if len(s) == 0 || len(s) > maxProbeURLLen {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

// settingsFrom applies the panel's config over the defaults, clamped.
// Invalid URLs are dropped; none left = the defaults.
func settingsFrom(c *pb.LatencyProbeConfig) probeSettings {
	s := defaultProbeSettings()
	if v := c.GetIntervalSeconds(); v > 0 {
		s.interval = min(max(time.Duration(v)*time.Second, minProbeInterval), maxProbeInterval)
	}
	if v := c.GetTimeoutMs(); v > 0 {
		s.timeout = min(max(time.Duration(v)*time.Millisecond, minProbeTimeout), maxProbeTimeout)
	}
	if v := c.GetAttempts(); v > 0 {
		s.attempts = int(min(v, maxProbeAttempts))
	}
	var urls []string
	for _, u := range c.GetUrls() {
		if validProbeURL(u) && len(urls) < maxProbeURLs && !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	if len(urls) > 0 {
		s.urls = urls
	}
	return s
}

// prober runs the scheduled and requested latency tests for the process
// lifetime (independent of streams); the latest result is (re)sent after
// every Hello.
type prober struct {
	mu        sync.Mutex
	set       probeSettings
	token     uint64
	haveToken bool
	latest    *pb.LatencyReport
	lastRun   time.Time

	kick    chan struct{} // run now (coalesced)
	resched chan struct{} // settings changed

	// Seams (tests).
	now     func() time.Time
	jitter  func() float64 // in [0, 1)
	measure func(ctx context.Context, url string, timeout time.Duration) (time.Duration, error)
}

func newProber() *prober {
	return &prober{
		set:     defaultProbeSettings(),
		kick:    make(chan struct{}, 1),
		resched: make(chan struct{}, 1),
		now:     time.Now,
		jitter:  rand.Float64,
		measure: measureOnce,
	}
}

// configure applies a LatencyProbeConfig from the panel. A new nonzero
// run_token asks for a test now, except the first token this process sees
// (it tests at startup anyway).
func (p *prober) configure(c *pb.LatencyProbeConfig) {
	s := settingsFrom(c)
	p.mu.Lock()
	changed := s.interval != p.set.interval
	p.set = s
	run := false
	if t := c.GetRunToken(); t != 0 && t != p.token {
		run = p.haveToken
		p.token, p.haveToken = t, true
	} else if t == 0 && !p.haveToken {
		p.haveToken = true
	}
	p.mu.Unlock()
	if run {
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
	if changed {
		select {
		case p.resched <- struct{}{}:
		default:
		}
	}
}

// latestReport: the last result (nil before the first run).
func (p *prober) latestReport() *pb.LatencyReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.latest
}

// loop runs tests until ctx ends: one soon after start, then every
// interval (+-10% jitter), plus requested runs (at most one per
// minProbeGap). deliver hands a fresh result to the current stream.
func (p *prober) loop(ctx context.Context, deliver func(*pb.LatencyReport)) {
	next := p.now().Add(time.Duration(p.jitter() * float64(startupProbeDelay)))
	pending := false // a coalesced request waits for `next`
	for {
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		requested := false
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-p.kick:
			timer.Stop()
			requested = true
		case <-p.resched:
			timer.Stop()
			p.mu.Lock()
			base := p.lastRun
			iv := p.set.interval
			p.mu.Unlock()
			if !base.IsZero() {
				next = base.Add(p.jittered(iv))
				if pending {
					// A coalesced "test now" keeps its slot: a new interval
					// only moves the scheduled run (W12: the request used to
					// be pushed out to the new interval).
					if due := base.Add(minProbeGap); due.Before(next) {
						next = due
					}
				}
			}
			continue
		}
		if requested {
			p.mu.Lock()
			last := p.lastRun
			p.mu.Unlock()
			if gap := p.now().Sub(last); !last.IsZero() && gap < minProbeGap {
				// Coalesce: run once the gap has passed.
				next = last.Add(minProbeGap)
				pending = true
				continue
			}
		}
		requested = requested || pending
		pending = false
		p.mu.Lock()
		set := p.set
		token := uint64(0)
		if requested {
			token = p.token
		}
		p.mu.Unlock()
		rep := p.run(ctx, set)
		if ctx.Err() != nil {
			return
		}
		rep.RunToken = token
		p.mu.Lock()
		p.latest = rep
		p.lastRun = p.now()
		next = p.lastRun.Add(p.jittered(set.interval))
		p.mu.Unlock()
		slog.Info("latency test", "results", summarize(rep))
		deliver(rep)
	}
}

func (p *prober) jittered(iv time.Duration) time.Duration {
	return time.Duration(float64(iv) * (0.9 + 0.2*p.jitter()))
}

// run tests the URLs in order and stops at the first that answered.
func (p *prober) run(ctx context.Context, set probeSettings) *pb.LatencyReport {
	rep := &pb.LatencyReport{}
	for _, u := range set.urls {
		r := p.measureURL(ctx, u, set.attempts, set.timeout)
		rep.Results = append(rep.Results, r)
		if r.Ok || ctx.Err() != nil {
			break
		}
	}
	rep.MeasuredAtUnix = p.now().Unix()
	return rep
}

// measureURL: `attempts` sequential attempts; median with failures counted
// as the timeout; ok iff any attempt succeeded.
func (p *prober) measureURL(ctx context.Context, u string, attempts int, timeout time.Duration) *pb.UrlLatency {
	r := &pb.UrlLatency{Url: u}
	vals := make([]time.Duration, 0, attempts)
	for range attempts {
		d, err := p.measure(ctx, u, timeout)
		if err != nil {
			r.AttemptsMs = append(r.AttemptsMs, 0)
			r.Error = shortError(err)
			vals = append(vals, timeout)
		} else {
			r.Ok = true
			r.AttemptsMs = append(r.AttemptsMs, durMs(d))
			vals = append(vals, d)
		}
		if ctx.Err() != nil {
			break
		}
	}
	if r.Ok {
		r.DelayMs = durMs(median(vals))
		r.Error = ""
	}
	return r
}

func durMs(d time.Duration) uint32 {
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1 // an answer is never "0 ms" (0 = failed)
	}
	return uint32(min(ms, 1<<31))
}

func median(v []time.Duration) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func shortError(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	s := err.Error()
	if len(s) > errMaxLen {
		s = s[:errMaxLen]
	}
	return s
}

func summarize(r *pb.LatencyReport) []string {
	out := make([]string, 0, len(r.Results))
	for _, x := range r.Results {
		if x.Ok {
			out = append(out, x.Url+"="+(time.Duration(x.DelayMs)*time.Millisecond).String())
		} else {
			out = append(out, x.Url+"=failed("+x.Error+")")
		}
	}
	return out
}

// measureOnce: one GET over a fresh direct connection; the delay ends when
// the response headers arrive. Any HTTP status counts as an answer (as
// Clash's url-test).
func measureOnce(ctx context.Context, u string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{
		Proxy:               nil, // the node's own egress, never HTTP(S)_PROXY
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A redirect is an answer: do not follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "akari-agent/latency")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	d := time.Since(start)
	_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	_ = resp.Body.Close()
	return d, nil
}
