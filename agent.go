package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"akari/agent/pb"
)

// agentProtocol is the control-protocol revision this agent speaks
// (Hello.protocol_version; see agent.proto). 2 = renews its certificate
// (AgentChannel.Renew); 3 = signed self-update (UpdateOffer/FetchArtifact);
// 4 = per-user speed limits (UserOp.speed_limit_bytes_per_sec, ratelimit.go);
// 5 = Shadowsocks 2022 removals apply in place as tombstones (W9: the panel
// sends them as deltas; WouldShrinkUnsafe); 6 = automatic node certificate
// over ACME (ConfigSnapshot.acme, Heartbeat.cert; acme.go); 7 (W28-a) =
// UserOp.user_id "<account>#<n>" per relay entrance: speed limits and the
// online-user count are per account (gate.go accountOf).
const agentProtocol = 7

// agentCapabilities: optional features independent of agentProtocol
// (Hello.capabilities, W11): "metrics" = Heartbeat.metrics, "latency" =
// LatencyProbeConfig / LatencyReport, "updater" = self-updates are applied
// by the privileged updater unit (W18, updater_linux.go), never by
// executing from the noexec state directory, "metrics-presence" (W23) = an
// unset numeric heartbeat value means "could not be read", not 0,
// "block-rules" (W29) = PanelDown.block_policy / Heartbeat.block.
// "source-filter" (W28-a) = ConfigSnapshot.source_filters enforced with
// nftables, Heartbeat.source_filter (sourcefilter.go).
var agentCapabilities = []string{"metrics", "latency", "updater", "metrics-presence", "block-rules", "source-filter"}

// capStaleUnits (W23): a status flag added to the capabilities when the
// installed systemd units differ from this release's (units.go).
const capStaleUnits = "stale-units"

// Agent is the node-side supervisor: one persistent mTLS gRPC stream to the
// panel, an embedded xray-core, and periodic heartbeat/traffic reporting.
type Agent struct {
	cfg          *Config
	core         *CoreManager
	agentVersion string
	ids          *identities
	startedAt    time.Time
	// capabilities: Hello.capabilities when not the default
	// agentCapabilities (W23: plus "stale-units"). Set before Run.
	capabilities []string

	// applyMu serializes everything that changes the running state: panel
	// messages (handleDown) and lease expiry.
	applyMu sync.Mutex

	mu         sync.Mutex
	heldConfig uint64
	heldUser   uint64
	// dirty: the running user set no longer matches the held versions (a
	// delta failed part-way, or an apply finished after its stream died).
	// Deltas are refused (BASE_MISMATCH) until the next clean Snapshot.
	dirty bool

	lease  *leaseState
	finals finalQueue
	// removeRebuild: panel agent.remove_mode = rebuild (LeaseGrant). Deltas
	// that remove or rotate a live credential are refused (BASE_MISMATCH)
	// so the change arrives as a Snapshot (full rebuild).
	removeRebuild bool

	streamMu  sync.Mutex
	streamGen uint64
	curSend   func(*pb.AgentUp) error // current stream's sender, nil if none
	// The current stream's connection (Renew goes over it), how to end
	// the stream (switch to a renewed certificate), whether it was dialed
	// with the pending renewed identity, and when it started.
	curConn    grpc.ClientConnInterface
	curCancel  context.CancelFunc
	curViaNext bool
	curStart   time.Time
	// curFlush waits until everything queued on the current stream was
	// handed to the transport (bounded by its timeout).
	curFlush func(timeout time.Duration)

	// certs: automatic node certificate (protocol 6); nil = disabled
	// (tests). Its loop runs for the whole process.
	certs *certManager
	// filters: relay entrances' source allowlists (W28-a); nil = disabled
	// (tests).
	filters *sourceFilters

	// Self-update (M6): nil when unavailable. trial is set when this
	// process runs a binary on probation.
	upd   *updater
	trial *trialState
	// procCtx: the process lifetime (Run's context). A stream's context
	// outlives a stop request (gracefulStop), so waits that hold applyMu
	// must also end on this one.
	procCtx context.Context
	// finalsPersisted: final counters were loaded from the update state
	// dir; the file goes once the queue has drained.
	finalsPersisted atomic.Bool
	// finalsStore: where unconfirmed final counters survive a restart
	// (graceful stop, self-update). nil falls back to the updater's
	// directory (tests); nil without an updater persists nothing.
	finalsStore *finalsStore
	// ckpt: the crash-safety checkpoint of the counters (checkpoint.go);
	// nil = none (tests). checkpointEvery bounds what a hard kill loses.
	ckpt            *checkpointStore
	checkpointEvery time.Duration
	// stopping: a graceful stop began; xray stays down.
	stopping atomic.Bool

	// W11: machine status sampler (owned by the running heartbeat loop;
	// one stream at a time) and the latency prober (process lifetime).
	sampler *sampler
	prober  *prober

	// skipNext: the last attempt with the pending renewed identity failed
	// for a reason that may be transient; the next attempt uses the
	// current one (then the renewed one again). Run's goroutine only.
	skipNext bool
	// Renewal backoff (a refused renewed certificate counts as a failure).
	renewMu       sync.Mutex
	renewFailures int
	renewRetryAt  time.Time

	// Seams (tests).
	dial         func(ctx context.Context, id *nodeIdentity) (*dialed, error)
	enrollRPC    func(ctx context.Context, req *pb.EnrollRequest) (*pb.IssuedCertificate, error)
	now          func() time.Time
	backoffBase  time.Duration
	leaseEvery   time.Duration
	trafficEvery time.Duration
	// How long a stream must stay up after carrying a final report before
	// the report is forgotten (see finalsConfirmAfter).
	finalsConfirm time.Duration
	// Bound on handing final counters to the transport at graceful stop.
	shutdownFlush time.Duration
	// sendStall: see the constant.
	sendStall       time.Duration
	heartbeatEvery  time.Duration
	renewCheckEvery time.Duration
	// How long a stream may run on the current certificate while a renewed
	// one waits for its first successful connection.
	nextRetryAfter time.Duration
	fetchBackoff   time.Duration
	exit           func(code int)
}

// dialed is an open stream and its connection.
type dialed struct {
	stream pb.AgentChannel_OpenChannelClient
	conn   grpc.ClientConnInterface
	close  func()
}

func NewAgent(cfg *Config, agentVersion string, ids *identities) *Agent {
	a := &Agent{
		cfg:             cfg,
		core:            NewCoreManager(),
		agentVersion:    agentVersion,
		ids:             ids,
		startedAt:       time.Now(),
		lease:           newLeaseState(bootClock),
		now:             time.Now,
		backoffBase:     time.Second,
		leaseEvery:      5 * time.Second,
		trafficEvery:    10 * time.Second,
		checkpointEvery: defaultCheckpointEvery,
		finalsConfirm:   finalsConfirmAfter,
		shutdownFlush:   5 * time.Second,
		sendStall:       sendStall,
		heartbeatEvery:  15 * time.Second,
		renewCheckEvery: 30 * time.Second,
		nextRetryAfter:  2 * time.Minute,
		fetchBackoff:    2 * time.Second,
		exit:            os.Exit,
		sampler:         newSampler(),
		prober:          newProber(),
	}
	a.dial = a.dialPanel
	a.enrollRPC = a.enrollPanel
	return a
}

func (a *Agent) versions() (config, user uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.heldConfig, a.heldUser
}

func (a *Agent) setVersions(config, user uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.heldConfig = config
	a.heldUser = user
}

func (a *Agent) isDirty() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dirty
}

func (a *Agent) setDirty(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dirty = d
}

// Run keeps the channel alive for the process lifetime, reconnecting with
// capped exponential backoff. The lease is enforced independently of any
// stream.
func (a *Agent) Run(ctx context.Context) error {
	a.procCtx = ctx
	err := a.run(ctx)
	if ctx.Err() != nil {
		// Graceful stop (SIGTERM): whatever the stream could not carry is
		// persisted for the next process (G3).
		a.stopped()
	}
	return err
}

func (a *Agent) run(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	go a.leaseLoop(ctx)
	go a.renewLoop(ctx)
	go a.checkpointLoop(ctx)
	go a.prober.loop(ctx, a.deliverLatency)
	if a.certs != nil {
		a.certs.onIssued = func(string) { a.onCertIssued() }
		go a.certs.run(ctx)
	}
	if a.trial != nil {
		go a.trialLoop(ctx)
	}
	backoff := a.backoffBase
	for {
		start := time.Now()
		err := a.session(ctx)
		// Measured before the backoff sleep: a stream that stayed up resets
		// the backoff (G4 - timing after the sleep could count the wait).
		lived := time.Since(start)
		if ctx.Err() != nil {
			return nil
		}
		wait := fullJitter(backoff)
		slog.Warn("channel closed", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		backoff = nextBackoff(backoff, a.backoffBase, lived)
	}
}

// fullJitter: a uniformly random wait in [0, d) ("full jitter", W6). Every
// node of a fleet loses its stream at the same moment when the panel
// restarts; without jitter they all reconnect (TLS handshake, desired-state
// read) in the same instant, at every step of the backoff.
func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return rand.N(d)
}

// stableStream: a stream that lived this long resets the reconnect backoff.
const stableStream = time.Minute

// nextBackoff is the delay after the one just waited: base again when the
// stream that just ended had been up for stableStream, else doubled, capped
// at 30 x base.
func nextBackoff(cur, base, lived time.Duration) time.Duration {
	if lived > stableStream {
		return base
	}
	return min(cur*2, 30*base)
}

func (a *Agent) dialPanel(ctx context.Context, id *nodeIdentity) (*dialed, error) {
	conn, err := a.clientConn(id)
	if err != nil {
		return nil, err
	}
	stream, err := pb.NewAgentChannelClient(conn).OpenChannel(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &dialed{stream: stream, conn: conn, close: func() { _ = conn.Close() }}, nil
}

// finalStore is where the final-counter queue is persisted (nil: nowhere).
func (a *Agent) finalStore() *finalsStore {
	switch {
	case a.finalsStore != nil:
		return a.finalsStore
	case a.upd != nil:
		return &finalsStore{dir: a.upd.dir}
	}
	return nil
}

// persistFinalsLocked writes the unconfirmed final reports to the state
// directory (the next process resends them; accounting is cumulative and
// idempotent, so duplicates are harmless). Caller holds applyMu. Reports
// whether the queue is now on disk (or empty).
func (a *Agent) persistFinalsLocked(why string) bool {
	st := a.finalStore()
	if st == nil {
		return false
	}
	reports := a.finals.all()
	if len(reports) == 0 {
		st.drop()
		return true
	}
	if err := st.save(reports); err != nil {
		// The reports also went out on the live stream (best effort) and
		// the panel's caps bound what can be lost.
		slog.Error("cannot persist final traffic counters", "why", why, "error", err)
		return false
	}
	a.finalsPersisted.Store(true)
	return true
}

// stopped: the process is stopping on a signal. Under the apply lock, xray
// is torn down (if still running: its counters become a final report) and
// every unconfirmed final report is persisted.
func (a *Agent) stopped() {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	a.stopping.Store(true) // no checkpoint after the finals are on disk
	if a.core.Running() {
		a.finals.add(a.core.Teardown())
	}
	if a.persistFinalsLocked("shutdown") && a.ckpt != nil {
		// finals.json now holds everything the checkpoint did.
		a.ckpt.clear()
	}
}

// gracefulStop runs on the live stream when the process is asked to stop:
// xray is torn down, its final counters are queued and sent, and the writer
// is given up to shutdownFlush to hand them to the transport. Caller holds
// no locks.
func (a *Agent) gracefulStop(gen uint64, send func(*pb.AgentUp) error, flush func(time.Duration)) {
	a.stopping.Store(true) // from here on panel messages are not applied
	a.applyMu.Lock()
	if a.core.Running() {
		a.finals.add(a.core.Teardown())
	}
	// Nothing runs any more: claim nothing, so a late reader cannot treat
	// the stale versions as current.
	a.setVersions(0, 0)
	a.setDirty(false)
	a.finals.flush(gen, send)
	a.applyMu.Unlock()
	flush(a.shutdownFlush)
}

// keepalive: a silently dead connection is noticed after Time + Timeout.
const (
	// sendQueue: upstream messages buffered for the writer.
	sendQueue = 256
	// sendStall: how long a send may wait for room in a full queue before
	// the stream is closed (C2). Longer than the keepalive's Time +
	// Timeout, so a dead connection is still left to the keepalive; this
	// only catches a live connection whose peer does not read.
	sendStall = keepaliveTime + keepaliveTimeout + 20*time.Second
	// maxRecvMsg: largest panel message accepted (C3). grpc-go's default
	// of 4 MiB is a Snapshot of ~18k users on two inbounds: past it the
	// stream died on every Snapshot and the node never converged.
	maxRecvMsg       = 64 << 20
	keepaliveTime    = 30 * time.Second
	keepaliveTimeout = 10 * time.Second
	// finalsConfirmAfter: a final report counts as delivered only after the
	// stream that carried it stayed up this long. It must exceed the time
	// a half-dead connection needs to be detected (keepalive Time + Timeout)
	// plus margin: a write into a dead socket "succeeds" locally, so an
	// earlier confirmation would drop a report the panel never got (G1).
	finalsConfirmAfter = keepaliveTime + keepaliveTimeout + 20*time.Second
)

// clientConn is a TLS connection to the panel, verified against the CA
// from the bootstrap file, presenting id's certificate (nil: none — only
// AgentEnrollment.Enroll accepts that).
func (a *Agent) clientConn(id *nodeIdentity) (*grpc.ClientConn, error) {
	tlsCfg := a.tlsConfig(id)
	return grpc.NewClient(
		a.cfg.PanelAddr,
		append(channelDialOptions(), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))...,
	)
}

// channelDialOptions: everything about the panel connection but its
// transport credentials (the tests dial with the same options).
func channelDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                keepaliveTime,
			Timeout:             keepaliveTimeout,
			PermitWithoutStream: true,
		}),
	}
}

// session runs one gRPC stream until it breaks. It returns only after every
// goroutine it started has exited — in particular the reader, which may be
// in the middle of a Rebuild: at most one handleDown runs at any time, and
// a dead stream's reader can never race the next stream's (F3).
func (a *Agent) session(parent context.Context) (err error) {
	// The stream outlives a stop request (parent): on SIGTERM the final
	// counters still go out on it (gracefulStop) before it is closed. Until
	// the stream is up a stop request just aborts the attempt.
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	defer cancel()
	var streamUp atomic.Bool
	go func() {
		select {
		case <-ctx.Done():
		case <-parent.Done():
			if !streamUp.Load() {
				cancel()
			}
		}
	}()

	id, viaNext := a.pickIdentity()
	if id == nil {
		return errors.New("no client certificate")
	}
	if now := a.now(); now.After(id.leaf.NotAfter) {
		slog.Error("client certificate expired: issue a new enrollment token (akari node enroll-token) "+
			"and put it in the bootstrap file", "not_after", id.leaf.NotAfter, "source", id.source)
	}
	// A stream dialed with the renewed identity proves it once the panel
	// sends anything (the panel only does after accepting the certificate).
	var gotMsg atomic.Bool
	if viaNext {
		defer func() {
			if gotMsg.Load() || parent.Err() != nil {
				return
			}
			if refusedCert(err) {
				slog.Error("panel refused the renewed certificate; keeping the current one", "error", err)
				a.ids.dropNext(id)
				a.renewFailed()
			} else {
				a.skipNext = true
			}
		}()
	}

	d, err := a.dial(ctx, id)
	if err != nil {
		return err
	}
	defer d.close()
	stream := d.stream
	slog.Info("channel established", "panel", a.cfg.PanelAddr, "identity", id.source,
		"cert_not_after", id.leaf.NotAfter)

	sendCh := make(chan *pb.AgentUp, sendQueue)
	done := make(chan error, 2)
	var stalled atomic.Bool
	defer func() {
		if stalled.Load() {
			err = errStreamStalled
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait() // runs after cancel (defers are LIFO)
	defer cancel()
	// Barriers: a message with no payload is never sent; the writer closes
	// its channel when it reaches it (everything queued before is out).
	var barriers sync.Map // *pb.AgentUp -> chan struct{}

	// Writer: serializes all upstream messages onto the stream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-sendCh:
				if msg.Msg == nil {
					if ch, ok := barriers.LoadAndDelete(msg); ok {
						if c, ok := ch.(chan struct{}); ok {
							close(c)
						}
					}
					continue
				}
				if err := stream.Send(msg); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	// send queues msg for the writer. It never blocks for long (C2): when
	// the queue stays full for sendStall (the connection is alive — the
	// keepalive would have ended it before — but the panel does not read)
	// the stream is cancelled, so whoever holds applyMu returns at once
	// and run() reconnects with backoff. Once the process is asked to
	// stop, a waiting send gets at most shutdownFlush more, so
	// gracefulStop takes applyMu (and finals are persisted) well within
	// systemd's TimeoutStopSec.
	send := func(msg *pb.AgentUp) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case sendCh <- msg:
			return nil
		default:
		}
		stall := time.NewTimer(a.sendStall)
		defer stall.Stop()
		stopping := parent.Done()
		for {
			select {
			case sendCh <- msg:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			case <-stopping:
				stopping = nil
				stall.Reset(a.shutdownFlush)
			case <-stall.C:
				slog.Warn("panel is not reading the stream; closing it", "queued", len(sendCh))
				stalled.Store(true)
				cancel()
				return errStreamStalled
			}
		}
	}

	flush := func(timeout time.Duration) {
		b := &pb.AgentUp{}
		ch := make(chan struct{})
		barriers.Store(b, ch)
		if send(b) != nil {
			barriers.Delete(b)
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
		case <-time.After(timeout):
		}
	}

	// Hello (and any final counters still owed) before anything else. The
	// apply lock keeps a concurrent lease expiry from interleaving.
	a.applyMu.Lock()
	gen := a.attachStream(send, d.conn, cancel, viaNext)
	a.streamMu.Lock()
	a.curFlush = flush
	a.streamMu.Unlock()
	err = send(a.helloLocked())
	if err == nil {
		// W1: the first periodic report on this stream is complete (the
		// panel instance behind it may never have seen these counters).
		a.core.ResetSent()
		a.finals.flush(gen, send)
		a.sendPendingReportLocked(gen, send)
		// W11: the latest latency result again (it may have been
		// measured while no stream was up; the panel upserts).
		if rep := a.prober.latestReport(); rep != nil {
			err = send(&pb.AgentUp{Msg: &pb.AgentUp_Latency{Latency: rep}})
		}
	}
	a.applyMu.Unlock()
	defer a.detachStream(gen)
	if err != nil {
		return err
	}
	streamUp.Store(true)
	wg.Add(4)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-parent.Done():
			a.gracefulStop(gen, send, flush)
			cancel()
		}
	}()
	go func() {
		defer wg.Done()
		heartbeatLoop(ctx, a.heartbeatEvery, send, a.lease.remaining, a.stats, a.sampler, a.fillHeartbeat)
	}()
	go func() {
		defer wg.Done()
		trafficLoop(ctx, a.trafficEvery, a.core, send, func() {
			a.finals.confirm(gen, a.finalsConfirm)
			if a.finals.len() == 0 && a.finalsPersisted.Swap(false) {
				if st := a.finalStore(); st != nil {
					st.drop()
				}
			}
		})
	}()
	// Reader: applies panel-pushed state.
	go func() {
		defer wg.Done()
		for {
			in, err := stream.Recv()
			if err != nil {
				done <- err
				return
			}
			if viaNext && !gotMsg.Swap(true) {
				if perr := a.ids.promote(id); perr != nil {
					slog.Error("failed to switch to the renewed certificate", "error", perr)
				} else {
					slog.Info("renewed certificate accepted by the panel", "cert_not_after", id.leaf.NotAfter)
				}
			}
			if err := a.handleDown(ctx, gen, send, in); err != nil {
				slog.Error("failed to handle panel message", "error", err)
			}
		}
	}()

	return <-done
}

func (a *Agent) attachStream(send func(*pb.AgentUp) error, conn grpc.ClientConnInterface, cancel context.CancelFunc, viaNext bool) uint64 {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	a.streamGen++
	a.curSend = send
	a.curConn, a.curCancel, a.curViaNext, a.curStart = conn, cancel, viaNext, a.now()
	return a.streamGen
}

func (a *Agent) detachStream(gen uint64) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.streamGen == gen {
		a.curSend = nil
		a.curConn, a.curCancel, a.curFlush = nil, nil, nil
	}
}

// pickIdentity: the pending renewed identity first, the current one when
// the last attempt with the renewed one failed (alternating).
func (a *Agent) pickIdentity() (*nodeIdentity, bool) {
	if next := a.ids.pending(); next != nil && !a.skipNext {
		return next, true
	}
	a.skipNext = false
	return a.ids.current(), false
}

// current returns the live stream's generation and sender (nil if none).
func (a *Agent) current() (uint64, func(*pb.AgentUp) error) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	return a.streamGen, a.curSend
}

func (a *Agent) helloCapabilities() []string {
	if a.capabilities != nil {
		return a.capabilities
	}
	return agentCapabilities
}

// helloLocked describes the agent's current state: the session its traffic
// counters belong to, the versions it holds and the hash of what it runs.
// Sent first on every stream and again after every Rebuild/teardown.
// Caller holds applyMu.
func (a *Agent) helloLocked() *pb.AgentUp {
	configVersion, userVersion := a.versions()
	return &pb.AgentUp{Msg: &pb.AgentUp_Hello{Hello: &pb.Hello{
		SessionId:       a.core.SessionID(),
		ConfigVersion:   configVersion,
		UserVersion:     userVersion,
		ProtocolVersion: agentProtocol,
		StateHash:       a.core.StateHash(configVersion),
		Capabilities:    a.helloCapabilities(),
		Info: &pb.AgentInfo{
			AgentVersion: a.agentVersion,
			CoreVersion:  core.Version(),
			Os:           runtime.GOOS,
			Arch:         runtime.GOARCH,
		},
	}}}
}

var errStreamGone = errors.New("stream closed before the message was handled")

// errStreamStalled: the panel kept the connection alive but stopped
// reading; the stream was closed (C2).
var errStreamStalled = errors.New("panel stopped reading the stream")

// handleDown applies one panel message. ctx is the stream's: once it is
// done nothing of the message may take effect (no Rebuild, no version
// change, no send), so a message from a dead stream can never be applied
// after the next stream's messages.
func (a *Agent) handleDown(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, in *pb.PanelDown) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if ctx.Err() != nil || a.stopping.Load() {
		return errStreamGone
	}

	switch msg := in.Msg.(type) {
	case *pb.PanelDown_Snapshot:
		return a.applySnapshotLocked(ctx, gen, send, msg.Snapshot)
	case *pb.PanelDown_Delta:
		return a.applyDeltaLocked(ctx, gen, send, msg.Delta)
	case *pb.PanelDown_Lease:
		if cur, _ := a.current(); cur != gen {
			slog.Warn("ignoring lease grant from a stale stream")
			return nil
		}
		d := a.lease.grant(msg.Lease.GetDurationSeconds())
		rebuild := msg.Lease.GetRemoveMode() == pb.RemoveMode_REMOVE_MODE_REBUILD
		if rebuild != a.removeRebuild {
			slog.Info("remove mode changed", "mode", msg.Lease.GetRemoveMode().String())
		}
		a.removeRebuild = rebuild
		slog.Debug("lease granted", "duration", d)
		return nil
	case *pb.PanelDown_UpdateOffer:
		return a.onUpdateOffer(ctx, gen, send, msg.UpdateOffer)
	case *pb.PanelDown_LatencyProbe:
		a.prober.configure(msg.LatencyProbe)
		return nil
	case *pb.PanelDown_BlockPolicy:
		if cur, _ := a.current(); cur != gen {
			slog.Warn("ignoring block policy from a stale stream")
			return nil
		}
		a.applyBlockPolicyLocked(send, msg.BlockPolicy)
		return nil
	case *pb.PanelDown_Noop:
		return nil
	case nil:
		return nil
	default:
		slog.Warn("unknown panel message type")
		return nil
	}
}

func (a *Agent) applySnapshotLocked(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, snap *pb.ConfigSnapshot) error {
	slog.Info("applying config snapshot",
		"config_version", snap.ConfigVersion,
		"user_version", snap.UserVersion,
		"users", len(snap.Users))
	a.configureCert(snap)
	// The allowlists go to the root updater first (R44: applied within
	// about a second; until then a new derived inbound relies on its
	// per-entrance credentials alone).
	if a.filters != nil {
		a.filters.Apply(snap.GetSourceFilters())
	}
	final, err := a.core.Rebuild(snap.InboundsJson, snap.Users)
	// The old instance's last counters (old session) are owed to the
	// panel whatever happens next: queue them (resent on reconnect).
	a.finals.add(final)
	if ctx.Err() != nil {
		// The stream died during the Rebuild: record nothing. The running
		// set is the snapshot's, the held versions stay older: dirty, so
		// the next stream converges through a Snapshot.
		a.setDirty(true)
		return errStreamGone
	}
	// Only a clean apply moves the held versions. On failure the agent
	// keeps claiming its previous versions (Hello), and the Ack reports
	// the ATTEMPTED versions with ok=false, so the panel can never mistake
	// a failed apply for convergence.
	if err == nil {
		a.setVersions(snap.ConfigVersion, snap.UserVersion)
		a.setDirty(false)
		a.logApplied("snapshot")
	} else {
		a.setDirty(true)
	}
	a.finals.flush(gen, send)
	// Counters restarted under a new session: announce it.
	if serr := send(a.helloLocked()); serr != nil {
		return serr
	}
	reason := pb.Ack_REASON_OK
	if err != nil {
		reason = pb.Ack_REASON_APPLY_FAILED
	}
	if aerr := a.sendAckLocked(send, snap.ConfigVersion, snap.UserVersion, reason, err); aerr != nil {
		return aerr
	}
	if err == nil {
		a.confirmTrialLocked(send)
	}
	return nil
}

func (a *Agent) applyDeltaLocked(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, d *pb.UserDelta) error {
	base := [2]uint64{d.BaseConfigVersion, d.BaseUserVersion}
	target := [2]uint64{d.ConfigVersion, d.UserVersion}
	hc, hu := a.versions()
	held := [2]uint64{hc, hu}
	slog.Info("applying user delta",
		"base_config_version", base[0], "base_user_version", base[1],
		"user_version", target[1], "ops", len(d.Ops))

	switch {
	case d.ConfigVersion != d.BaseConfigVersion:
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_APPLY_FAILED,
			fmt.Errorf("invalid delta: config_version %d != base_config_version %d", d.ConfigVersion, d.BaseConfigVersion))
	case held == target && !a.isDirty():
		// Idempotent resend: already there.
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_OK, nil)
	case held != base || a.isDirty() || !a.core.Running():
		why := fmt.Errorf("delta base %d/%d, agent holds %d/%d (dirty=%v)", base[0], base[1], held[0], held[1], a.isDirty())
		slog.Warn("rejecting user delta", "error", why)
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_BASE_MISMATCH, why)
	case a.removeRebuild && a.core.WouldDropCredential(d.Ops):
		why := fmt.Errorf("remove_mode=rebuild: removals/rotations need a snapshot")
		slog.Warn("rejecting user delta", "error", why)
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_BASE_MISMATCH, why)
	case a.core.WouldShrinkUnsafe(d.Ops):
		why := fmt.Errorf("shadowsocks credential change (rotation, re-add with a new key, or tombstone bound) needs a snapshot")
		slog.Warn("rejecting user delta", "error", why)
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_BASE_MISMATCH, why)
	}

	final, err := a.core.ApplyUserOps(d.Ops)
	// Removed users' last counters (current session) go out before the Ack.
	a.finals.add(final)
	if ctx.Err() != nil {
		a.setDirty(true)
		return errStreamGone
	}
	a.finals.flush(gen, send)
	if err != nil {
		// Partial failure: keep the base versions; what did apply is
		// visible in the state hash, and deltas wait for a Snapshot.
		a.setDirty(true)
		return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_APPLY_FAILED, err)
	}
	a.setVersions(target[0], target[1])
	a.logApplied("delta")
	if err := a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_OK, nil); err != nil {
		return err
	}
	a.confirmTrialLocked(send)
	return nil
}

// logApplied records a clean apply and what now runs (smoke keys on it).
func (a *Agent) logApplied(via string) {
	c, u := a.versions()
	slog.Info("state applied", "via", via, "config_version", c, "user_version", u,
		"users", a.core.UserCount(), "session", a.core.SessionID())
}

// sendAckLocked reports the ATTEMPTED versions plus what the agent holds
// now. Caller holds applyMu.
func (a *Agent) sendAckLocked(send func(*pb.AgentUp) error, configVersion, userVersion uint64, reason pb.Ack_Reason, err error) error {
	hc, hu := a.versions()
	ack := &pb.Ack{
		ConfigVersion:     configVersion,
		UserVersion:       userVersion,
		Ok:                reason == pb.Ack_REASON_OK,
		Reason:            reason,
		HeldConfigVersion: hc,
		HeldUserVersion:   hu,
		StateHash:         a.core.StateHash(hc),
	}
	if err != nil {
		ack.Error = err.Error()
		slog.Error("sending failure ack", "reason", reason.String(), "error", err)
	}
	return send(&pb.AgentUp{Msg: &pb.AgentUp_Ack{Ack: ack}})
}

// leaseLoop enforces the lease whether or not a stream is up.
func (a *Agent) leaseLoop(ctx context.Context) {
	t := time.NewTicker(a.leaseEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.checkLease()
	}
}

// checkLease tears xray down once the lease has run out: fail closed when
// the panel could not confirm the desired state for too long.
func (a *Agent) checkLease() {
	if !a.lease.check() {
		return
	}
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if !a.lease.check() || !a.core.Running() {
		return
	}
	slog.Error("panel lease expired: stopping xray until the panel confirms the desired state")
	a.finals.add(a.core.Teardown())
	// Nothing runs any more: claim nothing, so the next Hello forces a
	// Snapshot.
	a.setVersions(0, 0)
	a.setDirty(false)
	// If a stream is up (panel alive, database not), say so right away.
	if gen, send := a.current(); send != nil {
		if send(a.helloLocked()) == nil {
			a.finals.flush(gen, send)
		}
	}
}

// configureCert hands the Snapshot's ACME config to the certificate
// manager and points the next Rebuild at its files. Without ACME (or on a
// local error) TLS inbounds read the node certificate files as before.
// Caller holds applyMu.
func (a *Agent) configureCert(snap *pb.ConfigSnapshot) {
	if a.certs == nil {
		a.core.SetNodeCert(nil)
		return
	}
	f, ok, err := a.certs.Configure(snap.GetAcme(), snap.GetInboundsJson())
	if err != nil {
		slog.Error("automatic certificate unavailable; TLS inbounds read the node certificate files", "error", err)
	}
	if err != nil || !ok {
		a.core.SetNodeCert(nil)
		return
	}
	a.core.SetNodeCert(&f)
}

// onCertIssued: the first CA certificate replaced the placeholder. The TLS
// inbounds that serve it are swapped at once (other inbounds untouched);
// if that fails, the agent claims nothing (0,0) so the panel resends the
// Snapshot and the rebuild picks the certificate up.
func (a *Agent) onCertIssued() {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if a.stopping.Load() || !a.core.ServesPlaceholder() {
		return
	}
	err := a.core.ReloadInbounds()
	if err == nil {
		slog.Info("TLS inbounds now serve the CA-issued node certificate")
		return
	}
	slog.Error("could not swap the TLS inbounds onto the new certificate; asking the panel for a snapshot", "error", err)
	a.setVersions(0, 0)
	a.setDirty(true)
	if _, send := a.current(); send != nil {
		_ = send(a.helloLocked())
	}
}

// applyBlockPolicyLocked installs a W29 block policy (blockrules.go). A
// failed handler swap leaves the instance partly updated: like a failed
// certificate swap, the agent then claims nothing (0,0) so the panel sends
// a Snapshot, and the rebuild installs the policy cleanly.
func (a *Agent) applyBlockPolicyLocked(send func(*pb.AgentUp) error, p *pb.BlockPolicy) {
	err := a.core.SetBlockPolicy(p)
	if err == nil {
		slog.Info("block policy applied", "version", p.GetVersion(), "inbounds", len(p.GetInboundTags()), "rules", len(p.GetRules()))
		return
	}
	slog.Error("could not swap inbounds for the block policy; asking the panel for a snapshot", "error", err)
	a.setVersions(0, 0)
	a.setDirty(true)
	_ = send(a.helloLocked())
}

// fillHeartbeat: Heartbeat.cert (W10), Heartbeat.block (W29) and
// Heartbeat.source_filter (W28-a).
func (a *Agent) fillHeartbeat(hb *pb.Heartbeat) {
	hb.Cert = a.certStatus()
	hb.Block = a.core.BlockStats()
	hb.SourceFilter = a.sourceFilterStatus()
}

// sourceFilterStatus: Heartbeat.source_filter (nil when disabled or
// nothing was asked for).
func (a *Agent) sourceFilterStatus() *pb.SourceFilterStatus {
	if a.filters == nil {
		return nil
	}
	return a.filters.Status()
}

// certStatus: Heartbeat.cert (nil without ACME).
func (a *Agent) certStatus() *pb.CertStatus {
	if a.certs == nil {
		return nil
	}
	return a.certs.Status()
}

// deliverLatency sends a fresh latency result on the current stream, if
// any (otherwise it goes out after the next Hello).
func (a *Agent) deliverLatency(rep *pb.LatencyReport) {
	if _, send := a.current(); send != nil {
		_ = send(&pb.AgentUp{Msg: &pb.AgentUp_Latency{Latency: rep}})
	}
}

// stats: Heartbeat.connections (the gate's tracked dispatches), the
// distinct users among them (metrics.online_users) and uptime_seconds
// (since the agent process started).
func (a *Agent) stats() agentStats {
	conns, users := a.core.LiveStats()
	return agentStats{connections: conns, onlineUsers: users, uptime: uint64(time.Since(a.startedAt) / time.Second)}
}

func (a *Agent) tlsConfig(id *nodeIdentity) *tls.Config {
	c := &tls.Config{
		RootCAs:    a.ids.pool,
		ServerName: a.cfg.ServerName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
	if id != nil {
		c.Certificates = []tls.Certificate{id.cert}
	}
	return c
}

// finalQueue holds final counter reports of instances (or removed users)
// that must reach the panel. Accounting is idempotent (cumulative values per
// session), so a report is resent on every new stream until one stream has
// carried it and then stayed up for finalsConfirmAfter (longer than the
// keepalive death time, so a stream that was already dead cannot confirm).
type finalQueue struct {
	mu    sync.Mutex
	items []*finalItem
}

type finalItem struct {
	report *pb.TrafficReport
	sent   bool
	gen    uint64 // stream it was last sent on (if sent)
	sentAt time.Time
}

const maxFinals = 64

func (q *finalQueue) add(r *pb.TrafficReport) {
	if r == nil || len(r.Users) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, &finalItem{report: r})
	if len(q.items) > maxFinals {
		slog.Warn("dropping oldest unsent final traffic report", "session", q.items[0].report.SessionId)
		q.items = q.items[1:]
	}
}

// flush sends every report not yet sent on stream gen.
func (q *finalQueue) flush(gen uint64, send func(*pb.AgentUp) error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range q.items {
		if it.sent && it.gen == gen {
			continue
		}
		if sendTraffic(send, it.report) != nil {
			return
		}
		it.sent, it.gen, it.sentAt = true, gen, time.Now()
	}
}

// confirm drops reports sent on stream gen at least `after` ago (the stream
// has stayed up since).
func (q *finalQueue) confirm(gen uint64, after time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	kept := q.items[:0]
	for _, it := range q.items {
		if it.sent && it.gen == gen && time.Since(it.sentAt) >= after {
			continue
		}
		kept = append(kept, it)
	}
	q.items = kept
}

// all returns every queued report (persisted before a restart).
func (q *finalQueue) all() []*pb.TrafficReport {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*pb.TrafficReport, 0, len(q.items))
	for _, it := range q.items {
		out = append(out, it.report)
	}
	return out
}

func (q *finalQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
