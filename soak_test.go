//go:build soak

// Agent soak test (`make soak`, build tags canary + soak; never in CI).
//
// The REAL Agent (session, gate, rate limits, traffic loop, checkpoint,
// finals queue) runs against an in-process fake panel, while real xray
// clients in a child process (soak_client_test.go) hold long connections
// and open short ones continuously on six inbounds: VLESS+REALITY+Vision,
// VMess, Trojan over TLS, SS2022 multi-user, Hysteria 2 and a relay-derived
// inbound (users "<id>#1"). The panel churns the user set all the time
// (UserDelta add/remove/rotate/drop-inbound/speed-limit batches, a few
// thousand ghost users plus short-lived fresh ones), now and then sends a
// Snapshot (xray rebuild) and kills the stream (the agent reconnects), and
// grants leases.
//
// Every few seconds one "live" user is revoked or rotated; the child
// proves the old connection was cut and a new one refused. Every sample
// interval the harness records heap, RSS, goroutines, fds and the sizes of
// the agent's per-user maps; pprof profiles are taken at the start, the
// middle and the end. After the load stops, everything is drained and the
// process must return to its baseline. The panel side accounts traffic the
// way the real panel does (max per session and user) and the result is
// compared with the bytes the clients moved.
//
//	SOAK_DURATION=60m SOAK_OUT=<dir> go test -tags 'canary soak' -run TestSoak$ -timeout 0 -v .
//
// Knobs: SOAK_LIVE (live users, 5), SOAK_GHOSTS (ghost pool, 3000),
// SOAK_SNAPSHOT_EVERY (5m), SOAK_KILL_EVERY (3m), SOAK_SAMPLE (30s),
// SOAK_DRAIN (drain wait, 150s: longer than the 2min gone-counter grace).

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"akari/agent/pb"
)

type soakCfg struct {
	duration, snapEvery, killEvery, sample, drain time.Duration
	live, ghosts                                  int
	out                                           string
}

func envDur(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			panic(name + ": " + err.Error())
		}
		return d
	}
	return def
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			panic(name + ": " + err.Error())
		}
		return n
	}
	return def
}

func loadSoakCfg(t *testing.T) soakCfg {
	c := soakCfg{
		duration:  envDur("SOAK_DURATION", 60*time.Minute),
		snapEvery: envDur("SOAK_SNAPSHOT_EVERY", 5*time.Minute),
		killEvery: envDur("SOAK_KILL_EVERY", 3*time.Minute),
		sample:    envDur("SOAK_SAMPLE", 30*time.Second),
		drain:     envDur("SOAK_DRAIN", 150*time.Second),
		live:      envInt("SOAK_LIVE", 5),
		ghosts:    envInt("SOAK_GHOSTS", 3000),
		out:       os.Getenv("SOAK_OUT"),
	}
	if c.out == "" {
		c.out = t.TempDir()
	}
	if err := os.MkdirAll(c.out, 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------------------------------------------------------------- model

// sUser is one panel-side user id (an xray "email"): "<id>" on the direct
// inbounds, "<id>#1" on the relay-derived one.
type sUser struct {
	key   string
	relay bool
	tags  map[string]int // inbound tag -> credential generation
	limit uint64
}

func (u *sUser) tagNames() []string {
	names := make([]string, 0, len(u.tags))
	for t := range u.tags {
		names = append(names, t)
	}
	sort.Strings(names)
	return names
}

func (u *sUser) addOp() *pb.UserOp {
	op := &pb.UserOp{Op: pb.UserOp_ADD, UserId: u.key, SpeedLimitBytesPerSec: u.limit}
	for _, tag := range u.tagNames() {
		k := soakKindOf(tag)
		op.InboundUsers = append(op.InboundUsers, &pb.InboundUser{
			InboundTag: tag, Protocol: k.proto, AccountJson: soakCredential(k, u.key, u.tags[tag]).account})
	}
	return op
}

func directTags() []string {
	var r []string
	for _, k := range soakKinds {
		if !k.relay {
			r = append(r, k.tag)
		}
	}
	return r
}

// liveUser: a user with real clients. The direct and the relay entity share
// the fate of the user.
type liveUser struct {
	id         string
	direct     *sUser
	relay      *sUser
	childGen   map[string]int // slot tag -> generation the child's client uses
	present    bool
	next       time.Time
	cooldownTo time.Time
}

func (l *liveUser) entity(tag string) *sUser {
	if soakKindOf(tag).relay {
		return l.relay
	}
	return l.direct
}

type soakEvents struct {
	batches, deltas, snapshots, kills, resyncNone, resyncSnapshot, leases atomic.Int64
	ackNotOK, hashMismatch, fallbackSnapshots                             atomic.Int64
	revokes, revokedLive, cutOK, newRefused, rotations, restores, limits  atomic.Int64
	collateralChecked, collateralCut                                      atomic.Int64
	unverified, stalled                                                   atomic.Int64
	ghostBatches, ghostOps, freshAdded, freshRemoved                      atomic.Int64
	trafficReports, trafficRows, heartbeats                               atomic.Int64
}

type psStream struct {
	smu  sync.Mutex
	s    pb.AgentChannel_OpenChannelServer
	dead chan struct{}
	kill chan struct{}
}

func (p *psStream) send(m *pb.PanelDown) error {
	p.smu.Lock()
	defer p.smu.Unlock()
	return p.s.Send(m)
}

type soak struct {
	pb.UnimplementedAgentChannelServer
	t    *testing.T
	cfg  soakCfg
	rng  *rand.Rand // the driver goroutine
	rng2 *rand.Rand // the ghost goroutine
	log  *os.File

	env      *soakEnv
	menv     *matrixEnv
	inbounds string
	a        *Agent

	// model (driver goroutine mutates; mu guards readers)
	mu       sync.Mutex
	users    map[string]*sUser
	live     []*liveUser
	ghostIDs []string // direct ghosts
	ghostRel []string // relay ghosts
	ghostGen map[string]int
	fresh    []freshUser
	freshSeq int
	unique   atomic.Int64 // distinct user ids ever installed
	pairs    atomic.Int64 // distinct (user id, inbound) pairs ever installed
	// seenUsers: 64-bit hashes of every user key and (user, inbound) pair
	// ever installed (the harness's own memory: 8 B per entry, not the
	// strings, so the end-of-run heap comparison stays about the agent).
	seenUsers map[uint64]struct{}

	// versions the panel believes the agent holds / is being sent
	txMu        sync.Mutex // model mutation + its delta/snapshot (lock order: txMu, opMu)
	opMu        sync.Mutex
	cfgV, userV uint64
	cur         atomic.Pointer[psStream]
	ready       chan struct{} // closed when the current stream is synced
	readyMu     sync.Mutex
	acks        chan *pb.Ack
	streams     atomic.Int32

	// accounting (panel side, like the real panel: max per session+user)
	acctMu  sync.Mutex
	acct    map[[2]string][2]uint64
	rowsWin atomic.Int64
	lastHB  atomic.Pointer[pb.Heartbeat]

	child             *exec.Cmd
	cin               io.WriteCloser
	cmu               sync.Mutex
	pending           sync.Map // id -> chan *soakResp
	callID            atomic.Int64
	childPID          int
	lastOK, lastNanos int64

	ev         soakEvents
	violations []string
	vmu        sync.Mutex
	cutLat     []cutSample // guarded by vmu
}

type freshUser struct {
	key string
	due time.Time
}

func (h *soak) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05.000 ") + fmt.Sprintf(format, args...) + "\n"
	_, _ = os.Stdout.WriteString(line)
	_, _ = h.log.WriteString(line)
}

func (h *soak) violate(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	h.vmu.Lock()
	h.violations = append(h.violations, msg)
	h.vmu.Unlock()
	h.logf("VIOLATION: %s", msg)
}

func (h *soak) recs() []hashRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recsLocked()
}

func (h *soak) recsLocked() []hashRecord {
	var out []hashRecord
	for _, u := range h.users {
		for tag, gen := range u.tags {
			k := soakKindOf(tag)
			out = append(out, hashRecord{UserID: u.key, Tag: tag, Protocol: k.proto, Account: soakCredential(k, u.key, gen).account})
		}
	}
	return out
}

func (h *soak) expectedHash() string {
	return stateHash(h.cfgV, h.inbounds, h.recs())
}

// markSeen records key and reports whether it is new (callers hold h.mu).
func (h *soak) markSeen(key string) bool {
	f := fnv.New64a()
	_, _ = f.Write([]byte(key))
	k := f.Sum64()
	if _, ok := h.seenUsers[k]; ok {
		return false
	}
	h.seenUsers[k] = struct{}{}
	return true
}

func (h *soak) setUser(u *sUser) {
	h.mu.Lock()
	h.users[u.key] = u
	if h.markSeen(u.key) {
		h.unique.Add(1)
	}
	for tag := range u.tags {
		if h.markSeen(u.key + "|" + tag) {
			h.pairs.Add(1)
		}
	}
	h.mu.Unlock()
}

func (h *soak) delUser(key string) {
	h.mu.Lock()
	delete(h.users, key)
	h.mu.Unlock()
}

func (h *soak) allAddOps() []*pb.UserOp {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.users))
	for k := range h.users {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ops := make([]*pb.UserOp, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, h.users[k].addOp())
	}
	return ops
}

// ---------------------------------------------------------------- fake panel

func (h *soak) OpenChannel(s pb.AgentChannel_OpenChannelServer) error {
	n := h.streams.Add(1)
	ps := &psStream{s: s, dead: make(chan struct{}), kill: make(chan struct{})}
	defer close(ps.dead)
	var hello *pb.Hello
	for hello == nil {
		m, err := s.Recv()
		if err != nil {
			return nil
		}
		if x, ok := m.Msg.(*pb.AgentUp_Hello); ok {
			hello = x.Hello
		} else {
			h.onUp(m)
		}
	}
	// The reader goes on while the sync below waits for acks.
	go func() {
		for {
			m, err := s.Recv()
			if err != nil {
				return
			}
			h.onUp(m)
		}
	}()

	h.txMu.Lock()
	h.opMu.Lock()
	h.drainAcks()
	_ = ps.send(&pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 3600}}})
	h.ev.leases.Add(1)
	inSync := hello.ConfigVersion == h.cfgV && hello.UserVersion == h.userV && hello.StateHash == h.expectedHash()
	if inSync {
		h.ev.resyncNone.Add(1)
	} else {
		h.ev.resyncSnapshot.Add(1)
		if n > 1 {
			h.logf("stream %d: hello %d/%d hash-match=%v vs panel %d/%d: sending a snapshot",
				n, hello.ConfigVersion, hello.UserVersion, hello.StateHash == h.expectedHash(), h.cfgV, h.userV)
		}
		if err := h.snapshotLocked(ps); err != nil {
			h.logf("stream %d: initial snapshot: %v", n, err)
		}
	}
	h.readyMu.Lock()
	h.cur.Store(ps)
	close(h.ready)
	h.readyMu.Unlock()
	h.opMu.Unlock()
	h.txMu.Unlock()

	select {
	case <-ps.kill:
	case <-s.Context().Done():
	}
	h.readyMu.Lock()
	if h.cur.Load() == ps {
		h.cur.Store(nil)
		h.ready = make(chan struct{})
	}
	h.readyMu.Unlock()
	return nil
}

func (h *soak) onUp(m *pb.AgentUp) {
	switch x := m.Msg.(type) {
	case *pb.AgentUp_Ack:
		select {
		case h.acks <- x.Ack:
		default:
		}
	case *pb.AgentUp_Traffic:
		h.ev.trafficReports.Add(1)
		h.ev.trafficRows.Add(int64(len(x.Traffic.Users)))
		h.rowsWin.Add(int64(len(x.Traffic.Users)))
		h.acctMu.Lock()
		for _, r := range x.Traffic.Users {
			k := [2]string{x.Traffic.SessionId, r.UserId}
			cur := h.acct[k]
			h.acct[k] = [2]uint64{max(cur[0], r.UpBytes), max(cur[1], r.DownBytes)}
		}
		h.acctMu.Unlock()
	case *pb.AgentUp_Heartbeat:
		h.ev.heartbeats.Add(1)
		h.lastHB.Store(x.Heartbeat)
	}
}

func (h *soak) drainAcks() {
	for {
		select {
		case <-h.acks:
		default:
			return
		}
	}
}

func (h *soak) waitReady(timeout time.Duration) bool {
	h.readyMu.Lock()
	ch := h.ready
	h.readyMu.Unlock()
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

// waitAck waits for the ack of the given target versions on stream ps.
func (h *soak) waitAck(ps *psStream, cfg, user uint64) (*pb.Ack, error) {
	timeout := time.After(90 * time.Second)
	for {
		select {
		case a := <-h.acks:
			if a.ConfigVersion == cfg && a.UserVersion == user {
				return a, nil
			}
		case <-ps.dead:
			return nil, fmt.Errorf("stream ended")
		case <-timeout:
			return nil, fmt.Errorf("no ack for %d/%d", cfg, user)
		}
	}
}

// snapshotLocked sends the whole model as a Snapshot (a rebuild). opMu held.
func (h *soak) snapshotLocked(ps *psStream) error {
	h.cfgV++
	h.userV++
	snap := &pb.ConfigSnapshot{ConfigVersion: h.cfgV, UserVersion: h.userV, InboundsJson: h.inbounds, Users: h.allAddOps()}
	h.drainAcks()
	if err := ps.send(&pb.PanelDown{Msg: &pb.PanelDown_Snapshot{Snapshot: snap}}); err != nil {
		return err
	}
	h.ev.snapshots.Add(1)
	a, err := h.waitAck(ps, h.cfgV, h.userV)
	if err != nil {
		return err
	}
	if !a.Ok {
		h.ev.ackNotOK.Add(1)
		return fmt.Errorf("snapshot ack: %v %s", a.Reason, a.Error)
	}
	if want := h.expectedHash(); a.StateHash != want {
		h.ev.hashMismatch.Add(1)
		h.violate("state hash after snapshot %d/%d: agent %s panel %s", h.cfgV, h.userV, a.StateHash[:12], want[:12])
	}
	return nil
}

// sendDeltaLocked applies ops (the caller holds txMu) (the model already reflects them). On a refusal it
// falls back to a Snapshot. Returns false when the stream was gone (no
// verdict about the ops).
func (h *soak) sendDeltaLocked(ops []*pb.UserOp) bool {
	h.opMu.Lock()
	defer h.opMu.Unlock()
	ps := h.cur.Load()
	if ps == nil {
		return false
	}
	base := h.userV
	h.userV++
	d := &pb.UserDelta{UserVersion: h.userV, Ops: ops, BaseConfigVersion: h.cfgV, BaseUserVersion: base, ConfigVersion: h.cfgV}
	h.drainAcks()
	if err := ps.send(&pb.PanelDown{Msg: &pb.PanelDown_Delta{Delta: d}}); err != nil {
		return false
	}
	h.ev.deltas.Add(1)
	a, err := h.waitAck(ps, h.cfgV, h.userV)
	if err != nil {
		h.logf("delta %d: %v", h.userV, err)
		return false
	}
	if !a.Ok {
		h.ev.ackNotOK.Add(1)
		h.logf("delta %d refused: %v %s (falling back to a snapshot)", h.userV, a.Reason, a.Error)
		h.ev.fallbackSnapshots.Add(1)
		if err := h.snapshotLocked(ps); err != nil {
			h.logf("fallback snapshot: %v", err)
		}
		return true
	}
	if want := h.expectedHash(); a.StateHash != want {
		h.ev.hashMismatch.Add(1)
		h.violate("state hash after delta %d: agent %s panel %s (ops=%d)", h.userV, a.StateHash[:12], want[:12], len(ops))
	}
	return true
}

func (h *soak) sendSnapshot() {
	h.txMu.Lock()
	defer h.txMu.Unlock()
	h.opMu.Lock()
	defer h.opMu.Unlock()
	if ps := h.cur.Load(); ps != nil {
		if err := h.snapshotLocked(ps); err != nil {
			h.logf("snapshot: %v", err)
		}
	}
}

func (h *soak) killStream() {
	if ps := h.cur.Load(); ps != nil {
		h.ev.kills.Add(1)
		select {
		case <-ps.kill:
		default:
			close(ps.kill)
		}
	}
}

func (h *soak) sendLease() {
	if ps := h.cur.Load(); ps != nil {
		if ps.send(&pb.PanelDown{Msg: &pb.PanelDown_Lease{Lease: &pb.LeaseGrant{DurationSeconds: 3600}}}) == nil {
			h.ev.leases.Add(1)
		}
	}
}

// ---------------------------------------------------------------- child

func (h *soak) startChild(logPath string) {
	self, _ := os.Executable()
	cmd := exec.Command(self, "-test.run=^TestSoakChild$", "-test.count=1", "-test.timeout=0")
	cmd.Env = append(os.Environ(), "AKARI_SOAK_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		h.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		h.t.Fatal(err)
	}
	lf, err := os.Create(logPath)
	if err != nil {
		h.t.Fatal(err)
	}
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.child, h.cin, h.childPID = cmd, in, cmd.Process.Pid
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "@@") {
				_, _ = lf.WriteString(line + "\n")
				continue
			}
			var r soakResp
			if json.Unmarshal([]byte(line[2:]), &r) != nil {
				continue
			}
			if ch, ok := h.pending.LoadAndDelete(r.ID); ok {
				ch.(chan *soakResp) <- &r
			}
		}
	}()
}

func (h *soak) call(req soakReq) (*soakResp, error) {
	req.ID = h.callID.Add(1)
	ch := make(chan *soakResp, 1)
	h.pending.Store(req.ID, ch)
	b, _ := json.Marshal(&req)
	h.cmu.Lock()
	_, err := h.cin.Write(append(b, '\n'))
	h.cmu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		if r.Err != "" {
			return r, fmt.Errorf("child: %s", r.Err)
		}
		return r, nil
	case <-time.After(120 * time.Second):
		h.pending.Delete(req.ID)
		return nil, fmt.Errorf("child: no answer to %s", req.Op)
	}
}

func slotName(user, tag string) string { return user + "|" + tag }

func (h *soak) setSlot(user, tag string, gen int) {
	if _, err := h.call(soakReq{Op: "set", User: user, Tag: tag, Gen: gen}); err != nil {
		h.violate("child set %s|%s: %v", user, tag, err)
	}
}

// ---------------------------------------------------------------- process stats

type procSample struct {
	T           time.Duration
	HeapLive    uint64 // HeapAlloc right after a GC
	HeapInuse   uint64
	HeapSys     uint64
	RSS         uint64
	Goroutines  int
	FDs         int
	GateConns   int
	GateUsers   int
	GateAllowed int
	GateLive    int
	GateLimits  int
	Counted     int
	Gone        int
	Applied     int
	Issued      int
	StaleIssued int
	Finals      int
	Rows        int64
	ModelUsers  int
	Unique      int64
	ChildRSS    uint64
	ChildGor    int
	ChildFDs    int
	Mallocs     uint64
	Frees       uint64
	StackInuse  uint64
	NumGC       uint32
	AgentCPU    float64 // cumulative CPU seconds of this process (agent + fake panel)
	ChildCPU    float64
	// StuckTimers: goroutines deadlocked inside xray's ActivityTimer (see
	// stuckTimers).
	StuckTimers int
	ClientMB    float64 // cumulative bytes the clients wrote, MiB
	ShortOK     int64
	ShortFail   int64
	ShortMeanMs float64 // mean duration of the short connections since the last sample
}

func (h *soak) sample(t0 time.Time) procSample {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := procSample{
		T: time.Since(t0).Round(time.Second), HeapLive: ms.HeapAlloc, HeapInuse: ms.HeapInuse, HeapSys: ms.HeapSys,
		RSS: procRSS(), Goroutines: runtime.NumGoroutine(), FDs: procFDs(),
		Mallocs: ms.Mallocs, Frees: ms.Frees, StackInuse: ms.StackInuse, NumGC: ms.NumGC,
		Rows: h.rowsWin.Swap(0), Unique: h.unique.Load(), Finals: h.a.finals.len(),
	}
	h.mu.Lock()
	s.ModelUsers = len(h.users)
	h.mu.Unlock()
	m := h.a.core
	m.mu.Lock()
	s.Applied, s.Counted, s.Gone, s.StaleIssued = len(m.applied), len(m.counted), len(m.goneCounters), len(m.staleIssued)
	for _, v := range m.issued {
		s.Issued += len(v)
	}
	m.mu.Unlock()
	if g := m.liveGate.Load(); g != nil {
		g.mu.Lock()
		s.GateAllowed, s.GateLive, s.GateLimits = len(g.allowed), len(g.live), len(g.limits)
		g.mu.Unlock()
		c, u := g.LiveStats()
		s.GateConns, s.GateUsers = c, u
	}
	s.StuckTimers = stuckTimers()
	s.AgentCPU = procCPU("/proc/self/stat")
	if h.child != nil {
		s.ChildCPU = procCPU("/proc/" + strconv.Itoa(h.childPID) + "/stat")
		if r, err := h.call(soakReq{Op: "stats"}); err == nil && r.Stats != nil {
			var w, nanos int64
			for _, sl := range r.Stats.Slots {
				w += sl.Written
				s.ShortOK += sl.ShortOK
				s.ShortFail += sl.ShortFail
				nanos += sl.ShortNanos
			}
			s.ClientMB = float64(w) / (1 << 20)
			if d := s.ShortOK - h.lastOK; d > 0 {
				s.ShortMeanMs = float64(nanos-h.lastNanos) / float64(d) / 1e6
			}
			h.lastOK, h.lastNanos = s.ShortOK, nanos
		}
		s.ChildRSS = procStatusKB("/proc/"+strconv.Itoa(h.childPID)+"/status", "VmRSS:") * 1024
		if fds, err := os.ReadDir("/proc/" + strconv.Itoa(h.childPID) + "/fd"); err == nil {
			s.ChildFDs = len(fds)
		}
	}
	return s
}

func (s procSample) csvHeader() string {
	return "t_s,heap_live,heap_inuse,heap_sys,rss,goroutines,fds,gate_conns,gate_users,gate_allowed,gate_live_keys,gate_limits," +
		"counted,gone,applied,issued,stale_issued,finals,traffic_rows,model_users,unique_users,child_rss,child_fds,mallocs,frees,stack_inuse,num_gc," +
		"agent_cpu_s,child_cpu_s,client_written_mib,short_ok,short_fail,short_mean_ms,stuck_timers"
}

func (s procSample) csv() string {
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d,%d,%.2f,%d",
		int(s.T.Seconds()), s.HeapLive, s.HeapInuse, s.HeapSys, s.RSS, s.Goroutines, s.FDs, s.GateConns, s.GateUsers, s.GateAllowed,
		s.GateLive, s.GateLimits, s.Counted, s.Gone, s.Applied, s.Issued, s.StaleIssued, s.Finals, s.Rows, s.ModelUsers, s.Unique,
		s.ChildRSS, s.ChildFDs, s.Mallocs, s.Frees, s.StackInuse, s.NumGC,
		s.AgentCPU, s.ChildCPU, s.ClientMB, s.ShortOK, s.ShortFail, s.ShortMeanMs, s.StuckTimers)
}

// stuckTimers counts the goroutines blocked in xray's ActivityTimer.finish:
// SetTimeout holds the timer's lock while its first, synchronous check can
// call finish, which locks it again (common/signal/timer.go; the check of
// the task SetTimeout just replaced can take the activity token the
// synchronous one expects). The handler goroutine never returns, so its
// connection stays open, its task.Run never finishes, and everything the
// goroutine references (after a Rebuild: the whole old xray instance)
// stays reachable. Each is one connection that ended the way a connection
// ends, so they are a measure of the bug, not of the load.
func stuckTimers() int {
	var b strings.Builder
	if err := pprof.Lookup("goroutine").WriteTo(&b, 2); err != nil {
		return -1
	}
	n := 0
	for _, g := range strings.Split(b.String(), "\n\n") {
		if strings.Contains(g, "signal.(*ActivityTimer).finish") && strings.Contains(g, "sync.(*RWMutex).Lock") {
			n++
		}
	}
	return n
}

func (h *soak) profiles(tag string) {
	runtime.GC()
	for _, kind := range []string{"heap", "goroutine"} {
		f, err := os.Create(filepath.Join(h.cfg.out, fmt.Sprintf("%s-%s.pb.gz", kind, tag)))
		if err != nil {
			continue
		}
		_ = pprof.Lookup(kind).WriteTo(f, 0)
		_ = f.Close()
	}
	if f, err := os.Create(filepath.Join(h.cfg.out, "goroutine-"+tag+".txt")); err == nil {
		_ = pprof.Lookup("goroutine").WriteTo(f, 1)
		_ = f.Close()
	}
}

// ---------------------------------------------------------------- the test

func TestSoak(t *testing.T) {
	if os.Getenv("SOAK_DURATION") == "" && os.Getenv("SOAK_RUN") != "1" {
		t.Skip("set SOAK_DURATION (or SOAK_RUN=1) to run the soak test; see `make soak`")
	}
	cfg := loadSoakCfg(t)
	logf, err := os.Create(filepath.Join(cfg.out, "soak.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	agentLog, err := os.Create(filepath.Join(cfg.out, "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer agentLog.Close()
	slog.SetDefault(slog.New(slog.NewJSONHandler(agentLog, &slog.HandlerOptions{Level: slog.LevelInfo})))

	h := &soak{
		t: t, cfg: cfg, log: logf, rng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7)), rng2: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 11)),
		users: map[string]*sUser{}, ghostGen: map[string]int{}, seenUsers: map[uint64]struct{}{},
		ready: make(chan struct{}), acks: make(chan *pb.Ack, 64), acct: map[[2]string][2]uint64{},
	}
	h.logf("soak: duration %v, live users %d, ghosts %d, out %s", cfg.duration, cfg.live, cfg.ghosts, cfg.out)

	// Environment: certificates, REALITY keys, ports.
	h.menv = newMatrixEnv(t)
	h.env = &soakEnv{Pin: h.menv.pin, RealPub: h.menv.realityPub, Ports: map[string]int{}}
	h.env.SSPSK = "AAECAwQFBgcICQoLDA0ODw==" // 16 bytes
	for _, k := range soakKinds {
		h.env.Ports[k.tag] = freePort(t)
	}
	h.env.RealDest = tlsEcho(t, h.menv.cert)
	h.inbounds = soakInbounds(h.menv, h.env)

	// Live users and ghosts.
	for i := 0; i < cfg.live; i++ {
		id := fmt.Sprintf("live-%d", i)
		l := &liveUser{id: id, present: true, childGen: map[string]int{}}
		l.direct = &sUser{key: id, tags: map[string]int{}}
		l.relay = &sUser{key: id + "#1", relay: true, tags: map[string]int{}}
		for _, k := range soakKinds {
			l.entity(k.tag).tags[k.tag] = 0
		}
		l.next = time.Now().Add(time.Duration(10+h.rng.IntN(30)) * time.Second)
		h.live = append(h.live, l)
		h.setUser(l.direct)
		h.setUser(l.relay)
	}
	nRelay := cfg.ghosts / 5
	for i := 0; i < cfg.ghosts-nRelay; i++ {
		h.ghostIDs = append(h.ghostIDs, fmt.Sprintf("g%05d", i))
	}
	for i := 0; i < nRelay; i++ {
		h.ghostRel = append(h.ghostRel, fmt.Sprintf("g%05d#1", i))
	}
	for _, id := range h.ghostIDs[:len(h.ghostIDs)/2] {
		h.setUser(h.newGhost(id))
	}
	for _, id := range h.ghostRel[:len(h.ghostRel)/2] {
		h.setUser(h.newGhost(id))
	}

	// Fake panel + agent.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
	pb.RegisterAgentChannelServer(srv, h)
	go func() { _ = srv.Serve(l) }()
	defer srv.Stop()
	addr := l.Addr().String()
	stateDir := t.TempDir()
	a := NewAgent(&Config{PanelAddr: addr}, "soak", newTestCA(t).enrolledIDs(t))
	a.backoffBase = 500 * time.Millisecond
	a.finalsStore = &finalsStore{dir: stateDir}
	a.ckpt = &checkpointStore{dir: stateDir}
	a.dial = func(ctx context.Context, _ *nodeIdentity) (*dialed, error) {
		conn, err := grpc.NewClient(addr, append(channelDialOptions(), grpc.WithTransportCredentials(insecure.NewCredentials()))...)
		if err != nil {
			return nil, err
		}
		s, err := pb.NewAgentChannelClient(conn).OpenChannel(ctx)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &dialed{stream: s, conn: conn, close: func() { _ = conn.Close() }}, nil
	}
	h.a = a
	runCtx, stopAgent := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { _ = a.Run(runCtx); close(runDone) }()
	defer func() {
		stopAgent()
		select {
		case <-runDone:
		case <-time.After(30 * time.Second):
		}
		a.core.Teardown()
	}()

	if !h.waitReady(30 * time.Second) {
		t.Fatal("the agent never connected")
	}
	h.startChild(filepath.Join(cfg.out, "child.log"))
	defer func() {
		_ = h.cin.Close()
		done := make(chan struct{})
		go func() { _ = h.child.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = h.child.Process.Kill()
		}
	}()
	if _, err := h.call(soakReq{Op: "init", Env: h.env}); err != nil {
		t.Fatal(err)
	}

	// Baseline: the Snapshot with the initial users is applied; no client yet.
	time.Sleep(10 * time.Second)
	t0 := time.Now()
	base := h.sample(t0)
	h.logf("baseline: heap_live=%dKiB rss=%dMiB goroutines=%d fds=%d users=%d counted=%d issued=%d",
		base.HeapLive>>10, base.RSS>>20, base.Goroutines, base.FDs, base.ModelUsers, base.Counted, base.Issued)
	h.profiles("start")

	// Start the clients of every live user.
	for _, l := range h.live {
		for _, k := range soakKinds {
			h.setSlot(l.entity(k.tag).key, k.tag, 0)
			l.childGen[k.tag] = 0
		}
	}
	h.logf("clients up: %d slots", len(h.live)*len(soakKinds))

	csv, err := os.Create(filepath.Join(cfg.out, "samples.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer csv.Close()
	fmt.Fprintln(csv, base.csvHeader())
	fmt.Fprintln(csv, base.csv())
	var samples []procSample
	samples = append(samples, base)

	loadStart := time.Now()
	loadEnd := loadStart.Add(cfg.duration)
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	var smu sync.Mutex
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(cfg.sample)
		defer tick.Stop()
		midDone := false
		for {
			select {
			case <-stopSampler:
				return
			case <-tick.C:
			}
			s := h.sample(t0)
			smu.Lock()
			samples = append(samples, s)
			smu.Unlock()
			fmt.Fprintln(csv, s.csv())
			h.logf("t=%v heap=%dKiB inuse=%dKiB rss=%dMiB gor=%d fds=%d gate=%d/%d counted=%d gone=%d issued=%d stale=%d fin=%d rows=%d users=%d uniq=%d cpu=%.0fs short=%dms moved=%.0fMiB stuck=%d child(rss=%dMiB fds=%d cpu=%.0fs)",
				s.T, s.HeapLive>>10, s.HeapInuse>>10, s.RSS>>20, s.Goroutines, s.FDs, s.GateConns, s.GateLive, s.Counted, s.Gone,
				s.Issued, s.StaleIssued, s.Finals, s.Rows, s.ModelUsers, s.Unique, s.AgentCPU, int(s.ShortMeanMs), s.ClientMB, s.StuckTimers,
				s.ChildRSS>>20, s.ChildFDs, s.ChildCPU)
			if !midDone && time.Since(loadStart) >= cfg.duration/2 {
				midDone = true
				h.profiles("mid")
			}
		}
	}()

	h.driveLoad(loadEnd)
	h.logf("load phase over after %v", time.Since(loadStart).Round(time.Second))
	h.profiles("end-load")
	if st, err := h.call(soakReq{Op: "stats"}); err == nil {
		h.logChildStats(st.Stats)
	}

	// ---- stop the clients; everything is drained
	if _, err := h.call(soakReq{Op: "stop_all"}); err != nil {
		t.Errorf("stop_all: %v", err)
	}
	h.logf("clients stopped; waiting for the counters to settle")
	time.Sleep(40 * time.Second)
	idle := h.sample(t0)
	h.logf("idle (clients gone, users installed): conns=%d gor=%d fds=%d", idle.GateConns, idle.Goroutines, idle.FDs)

	h.checkAccounting()

	// ---- remove every user and wait out the grace periods
	h.removeAllUsers()
	h.logf("all users removed; draining for %v", cfg.drain)
	time.Sleep(cfg.drain)
	drained := h.sample(t0)
	smu.Lock()
	samples = append(samples, drained)
	smu.Unlock()
	fmt.Fprintln(csv, drained.csv())
	h.logf("drained: heap_live=%dKiB rss=%dMiB gor=%d fds=%d counted=%d gone=%d issued=%d stale=%d gate=%d/%d/%d finals=%d",
		drained.HeapLive>>10, drained.RSS>>20, drained.Goroutines, drained.FDs, drained.Counted, drained.Gone, drained.Issued,
		drained.StaleIssued, drained.GateAllowed, drained.GateLive, drained.GateLimits, drained.Finals)
	h.profiles("drained")

	// ---- an empty Snapshot: a rebuild; the process must be back at baseline
	h.sendSnapshot()
	time.Sleep(20 * time.Second)
	end := h.sample(t0)
	fmt.Fprintln(csv, end.csv())
	h.logf("rebuilt empty: heap_live=%dKiB rss=%dMiB gor=%d fds=%d counted=%d issued=%d",
		end.HeapLive>>10, end.RSS>>20, end.Goroutines, end.FDs, end.Counted, end.Issued)
	h.profiles("final")
	close(stopSampler)
	<-samplerDone

	h.summary(base, idle, drained, end, samples)
	h.assertEnd(t, base, drained, end, samples)
}

func (h *soak) logChildStats(st *soakStats) {
	if st == nil {
		return
	}
	var w, r, ok, fail, deaths, dials, sets int64
	for _, s := range st.Slots {
		w += s.Written
		r += s.Read
		ok += s.ShortOK
		fail += s.ShortFail
		deaths += s.LongDeaths
		dials += s.Dials
		sets += s.Sets
	}
	h.logf("clients: wrote %.2f GiB, read %.2f GiB, short conns ok=%d fail=%d, long deaths=%d, dials=%d, instance sets=%d (child rss=%dMiB gor=%d fds=%d)",
		float64(w)/(1<<30), float64(r)/(1<<30), ok, fail, deaths, dials, sets, st.RSS>>20, st.Goroutines, st.FDs)
}

func (h *soak) removeAllUsers() {
	h.mu.Lock()
	var ops []*pb.UserOp
	for k := range h.users {
		ops = append(ops, &pb.UserOp{Op: pb.UserOp_REMOVE, UserId: k})
	}
	h.users = map[string]*sUser{}
	h.mu.Unlock()
	for len(ops) > 0 {
		n := min(len(ops), 500)
		// The model is already empty: send the removals in chunks, then
		// verify the hash only at the end.
		h.sendRawDelta(ops[:n])
		ops = ops[n:]
	}
	h.opMu.Lock()
	h.logf("after removing everything: panel hash %s", h.expectedHash()[:12])
	h.opMu.Unlock()
}

// sendRawDelta: a delta without the model-hash check (bulk removal).
func (h *soak) sendRawDelta(ops []*pb.UserOp) {
	h.opMu.Lock()
	defer h.opMu.Unlock()
	ps := h.cur.Load()
	if ps == nil {
		h.violate("bulk removal without a stream")
		return
	}
	base := h.userV
	h.userV++
	d := &pb.UserDelta{UserVersion: h.userV, Ops: ops, BaseConfigVersion: h.cfgV, BaseUserVersion: base, ConfigVersion: h.cfgV}
	h.drainAcks()
	if err := ps.send(&pb.PanelDown{Msg: &pb.PanelDown_Delta{Delta: d}}); err != nil {
		h.violate("bulk removal: %v", err)
		return
	}
	a, err := h.waitAck(ps, h.cfgV, h.userV)
	if err != nil || !a.Ok {
		h.violate("bulk removal ack: %v %v", err, a)
	}
}

// procCPU: user+system CPU seconds of a process (from /proc/<pid>/stat).
func procCPU(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	// Fields after the parenthesised command name; utime and stime are
	// fields 14 and 15 of the whole line.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(b)[i+1:])
	if len(f) < 13 {
		return 0
	}
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	return (ut + st) / 100 // USER_HZ
}
