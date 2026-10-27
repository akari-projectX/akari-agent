//go:build soak

// The soak test's client process. The parent (soak_test.go) re-executes the
// test binary with AKARI_SOAK_CHILD=1 and drives this test over stdin/stdout
// (one JSON object per line). Keeping the xray clients out of the agent's
// process keeps the agent's heap, goroutine and fd numbers its own.
//
// Per slot (user, inbound) it runs one real xray client instance, one
// long-lived connection (echo ping every 1-2s, a bulk echo now and then)
// and a stream of short connections, and counts the raw bytes written to
// and read back from the client instance's local port.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
)

type soakReq struct {
	ID    int64    `json:"id"`
	Op    string   `json:"op"`
	Env   *soakEnv `json:"env,omitempty"`
	User  string   `json:"user,omitempty"`
	Tag   string   `json:"tag,omitempty"`
	Gen   int      `json:"gen,omitempty"`
	Slots []string `json:"slots,omitempty"`
}

type soakResp struct {
	ID      int64      `json:"id"`
	Err     string     `json:"err,omitempty"`
	Live    []string   `json:"live,omitempty"`
	Alive   []string   `json:"alive,omitempty"` // slots whose long connection is still up
	Cut     []string   `json:"cut,omitempty"`
	NotCut  []string   `json:"not_cut,omitempty"`
	Allowed []string   `json:"allowed,omitempty"` // slots a new connection got through on
	Stats   *soakStats `json:"stats,omitempty"`
}

type slotStats struct {
	Slot       string `json:"slot"`
	User       string `json:"user"`
	TLS        bool   `json:"tls"` // inner TLS: raw byte counts include the handshakes
	Written    int64  `json:"written"`
	Read       int64  `json:"read"`
	ShortOK    int64  `json:"short_ok"`
	ShortFail  int64  `json:"short_fail"`
	LongPings  int64  `json:"long_pings"`
	LongDeaths int64  `json:"long_deaths"`
	Dials      int64  `json:"dials"`
	ShortNanos int64  `json:"short_nanos"` // total duration of the successful short connections
	Sets       int64  `json:"sets"`
}

type soakStats struct {
	Slots      []slotStats `json:"slots"`
	RSS        uint64      `json:"rss"`
	Goroutines int         `json:"goroutines"`
	FDs        int         `json:"fds"`
}

type soakSlot struct {
	name, user, tag string
	kind            soakKind

	mu     sync.Mutex
	inst   *core.Instance
	port   int  // the client instance's local dokodemo port
	active bool // workers may start new connections
	epoch  int  // bumped by every set

	longAlive atomic.Bool
	lastPing  atomic.Int64 // unix nanos of the last successful long echo

	written, read                  atomic.Int64
	shortOK, shortFail, shortNanos atomic.Int64
	longPings, longDeaths, dials   atomic.Int64
	sets                           atomic.Int64
	stop                           chan struct{}
	workersStarted                 bool
}

type soakChild struct {
	t       *testing.T
	env     *soakEnv
	menv    *matrixEnv
	plain   int // plain echo
	tlsPort int // TLS 1.3 echo (Vision slots)
	wmu     sync.Mutex
	out     *bufio.Writer

	mu    sync.Mutex
	slots map[string]*soakSlot
	quit  chan struct{}
}

func TestSoakChild(t *testing.T) {
	if os.Getenv("AKARI_SOAK_CHILD") != "1" {
		t.Skip("child process of the soak test")
	}
	c := &soakChild{t: t, slots: map[string]*soakSlot{}, out: bufio.NewWriter(os.Stdout), quit: make(chan struct{})}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var req soakReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			fmt.Fprintf(os.Stderr, "child: bad request: %v\n", err)
			continue
		}
		if req.Op == "quit" {
			break
		}
		go func() {
			resp := c.handle(&req)
			resp.ID = req.ID
			c.reply(resp)
		}()
	}
	c.stopAll()
}

func (c *soakChild) reply(r *soakResp) {
	b, _ := json.Marshal(r)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, _ = c.out.WriteString("@@" + string(b) + "\n")
	_ = c.out.Flush()
}

func (c *soakChild) handle(req *soakReq) (resp *soakResp) {
	defer func() {
		if r := recover(); r != nil {
			resp = &soakResp{Err: fmt.Sprint("panic: ", r)}
		}
	}()
	switch req.Op {
	case "init":
		c.env = req.Env
		c.menv = &matrixEnv{pin: req.Env.Pin, realityPub: req.Env.RealPub}
		_, _, cert := selfSigned(c.t)
		c.plain = echoServerQuiet(c.t)
		c.tlsPort = tlsEchoQuiet(c.t, cert)
		return &soakResp{}
	case "set":
		return c.set(req)
	case "prep":
		var live []string
		for _, n := range req.Slots {
			if s := c.slot(n); s != nil && s.isLive() {
				live = append(live, n)
			}
		}
		return &soakResp{Live: live}
	case "alive":
		var alive []string
		for _, n := range req.Slots {
			if s := c.slot(n); s != nil && s.isLive() {
				alive = append(alive, n)
			}
		}
		return &soakResp{Alive: alive}
	case "expect_cut":
		return c.expectCut(req.Slots)
	case "resume":
		for _, n := range req.Slots {
			if s := c.slot(n); s != nil {
				s.mu.Lock()
				s.active = true
				s.mu.Unlock()
			}
		}
		return &soakResp{}
	case "stats":
		return &soakResp{Stats: c.stats()}
	case "stop_all":
		c.stopAll()
		return &soakResp{}
	}
	return &soakResp{Err: "unknown op " + req.Op}
}

func (c *soakChild) slot(name string) *soakSlot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slots[name]
}

func (s *soakSlot) isLive() bool {
	s.mu.Lock()
	act := s.active
	s.mu.Unlock()
	return act && s.longAlive.Load() && time.Since(time.Unix(0, s.lastPing.Load())) < 4*time.Second
}

// set (re)creates the slot's client instance for the credential generation
// and lets the workers run.
func (c *soakChild) set(req *soakReq) *soakResp {
	kind := soakKindOf(req.Tag)
	name := req.User + "|" + req.Tag
	c.mu.Lock()
	s := c.slots[name]
	if s == nil {
		s = &soakSlot{name: name, user: req.User, tag: req.Tag, kind: kind, stop: make(chan struct{})}
		c.slots[name] = s
	}
	c.mu.Unlock()
	cred := soakCredential(kind, req.User, req.Gen)
	target := c.plain
	if kind.innerTLS {
		target = c.tlsPort
	}
	cp := freePortQuiet()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": cp, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1", "port": target, "network": "tcp"}}},
		"outbounds": []any{soakOutbound(c.menv, c.env, kind, cred)},
	}
	inst, err := startClientInstance(cfg)
	if err != nil {
		return &soakResp{Err: err.Error()}
	}
	s.mu.Lock()
	old := s.inst
	s.inst, s.port, s.active = inst, cp, true
	s.epoch++
	start := !s.workersStarted
	s.workersStarted = true
	s.mu.Unlock()
	s.sets.Add(1)
	if old != nil {
		_ = old.Close()
	}
	if start {
		go s.longLoop()
		go s.shortLoop()
	}
	return &soakResp{}
}

// expectCut: the revocation checks for slots whose credential the panel
// just removed or replaced. Every slot gets: its long connection must close
// within 6s; a new connection through the same client instance must not
// relay (probed 3 times). The slots then stay paused until set/resume.
func (c *soakChild) expectCut(names []string) *soakResp {
	resp := &soakResp{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		s := c.slot(n)
		if s == nil {
			continue
		}
		s.mu.Lock()
		s.active = false // no new connections from the workers
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			cut := false
			for end := time.Now().Add(6 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
				if !s.longAlive.Load() {
					cut = true
					break
				}
			}
			allowed := false
			for i := 0; i < 3; i++ {
				if s.probe() == nil {
					allowed = true
				}
				time.Sleep(150 * time.Millisecond)
			}
			mu.Lock()
			defer mu.Unlock()
			if cut {
				resp.Cut = append(resp.Cut, n)
			} else {
				resp.NotCut = append(resp.NotCut, n)
			}
			if allowed {
				resp.Allowed = append(resp.Allowed, n)
			}
		}()
	}
	wg.Wait()
	return resp
}

// probe: one new connection through the slot's client instance with a
// small echo (nil = it relayed). A server that silently drains an unknown
// user (SS2022, VMess) leaves the client waiting: that is a refusal too.
func (s *soakSlot) probe() error {
	s.mu.Lock()
	port := s.port
	s.mu.Unlock()
	cn, err := s.dial(port, 3*time.Second)
	if err != nil {
		return err
	}
	defer cn.Close()
	return soakEcho(cn, 512, 3*time.Second)
}

// countConn counts the raw bytes at the client instance's local port.
type countConn struct {
	net.Conn
	s *soakSlot
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.s.written.Add(int64(n))
	return n, err
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.s.read.Add(int64(n))
	return n, err
}

func (s *soakSlot) dial(port int, handshake time.Duration) (net.Conn, error) {
	s.dials.Add(1)
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		return nil, err
	}
	var c net.Conn = &countConn{Conn: raw, s: s}
	if s.kind.innerTLS {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		_ = tc.SetDeadline(time.Now().Add(handshake))
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			return nil, err
		}
		_ = tc.SetDeadline(time.Time{})
		c = tc
	}
	return c, nil
}

// soakEcho sends n random bytes and expects them back.
func soakEcho(c net.Conn, n int, within time.Duration) error {
	_ = c.SetDeadline(time.Now().Add(within))
	defer c.SetDeadline(time.Time{})
	msg := make([]byte, n)
	for i := range msg {
		msg[i] = byte(i*7 + n)
	}
	werr := make(chan error, 1)
	go func() { _, err := c.Write(msg); werr <- err }()
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		<-werr
		return err
	}
	if err := <-werr; err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

func (s *soakSlot) target() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port, s.active
}

func (s *soakSlot) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

func sleepOr(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return false
	case <-time.After(d):
		return true
	}
}

func (s *soakSlot) longLoop() {
	for !s.stopped() {
		port, ok := s.target()
		if !ok {
			if !sleepOr(s.stop, 200*time.Millisecond) {
				return
			}
			continue
		}
		cn, err := s.dial(port, 8*time.Second)
		if err == nil {
			err = soakEcho(cn, 256, 20*time.Second)
		}
		if err != nil {
			if cn != nil {
				_ = cn.Close()
			}
			if !sleepOr(s.stop, 500*time.Millisecond) {
				return
			}
			continue
		}
		s.longAlive.Store(true)
		s.lastPing.Store(time.Now().UnixNano())
		for i := 1; ; i++ {
			if !sleepOr(s.stop, time.Second+time.Duration(rand.IntN(1000))*time.Millisecond) {
				_ = cn.Close()
				return
			}
			n := 1024
			if i%10 == 0 {
				n = 512 << 10
			}
			if err := soakEcho(cn, n, 20*time.Second); err != nil {
				break
			}
			s.longPings.Add(1)
			s.lastPing.Store(time.Now().UnixNano())
		}
		_ = cn.Close()
		s.longAlive.Store(false)
		s.longDeaths.Add(1)
	}
}

func (s *soakSlot) shortLoop() {
	for !s.stopped() {
		port, ok := s.target()
		if !ok {
			if !sleepOr(s.stop, 200*time.Millisecond) {
				return
			}
			continue
		}
		began := time.Now()
		cn, err := s.dial(port, 8*time.Second)
		if err == nil {
			err = soakEcho(cn, 512+rand.IntN(48<<10), 20*time.Second)
			_ = cn.Close()
		}
		if _, still := s.target(); still { // a failure while paused is expected
			if err == nil {
				s.shortOK.Add(1)
				s.shortNanos.Add(int64(time.Since(began)))
			} else {
				s.shortFail.Add(1)
			}
		}
		if !sleepOr(s.stop, 100*time.Millisecond+time.Duration(rand.IntN(300))*time.Millisecond) {
			return
		}
	}
}

func (c *soakChild) stats() *soakStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &soakStats{Goroutines: runtime.NumGoroutine()}
	for _, s := range c.slots {
		st.Slots = append(st.Slots, slotStats{
			Slot: s.name, User: s.user, TLS: s.kind.innerTLS, Written: s.written.Load(), Read: s.read.Load(),
			ShortOK: s.shortOK.Load(), ShortNanos: s.shortNanos.Load(), ShortFail: s.shortFail.Load(), LongPings: s.longPings.Load(),
			LongDeaths: s.longDeaths.Load(), Dials: s.dials.Load(), Sets: s.sets.Load(),
		})
	}
	st.RSS = procRSS()
	st.FDs = procFDs()
	return st
}

func (c *soakChild) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.slots {
		s.mu.Lock()
		s.active = false
		inst := s.inst
		s.inst = nil
		s.mu.Unlock()
		select {
		case <-s.stop:
		default:
			close(s.stop)
		}
		if inst != nil {
			_ = inst.Close()
		}
	}
}

func startClientInstance(cfg map[string]any) (*core.Instance, error) {
	b, _ := json.Marshal(cfg)
	jc, err := confserial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	pc, err := jc.Build()
	if err != nil {
		return nil, err
	}
	inst, err := core.New(pc)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, err
	}
	return inst, nil
}

func freePortQuiet() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func echoServerQuiet(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(l)
	return l.Addr().(*net.TCPAddr).Port
}

func tlsEchoQuiet(t *testing.T, cert tls.Certificate) int {
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	go serveEcho(l)
	return l.Addr().(*net.TCPAddr).Port
}

func serveEcho(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
	}
}

// procRSS / procFDs: this process's resident set and open descriptors.
func procRSS() uint64 { return procStatusKB("/proc/self/status", "VmRSS:") * 1024 }

func procStatusKB(path, key string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(ln, key); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				v, _ := strconv.ParseUint(f[0], 10, 64)
				return v
			}
		}
	}
	return 0
}

func procFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents) - 1 // the directory handle itself
}
