package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/xtls/xray-core/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"akari/agent/pb"
)

// agentProtocol is the control-protocol revision this agent speaks
// (Hello.protocol_version; see agent.proto).
const agentProtocol = 1

// Agent is the node-side supervisor: one persistent mTLS gRPC stream to the
// panel, an embedded xray-core, and periodic heartbeat/traffic reporting.
type Agent struct {
	cfg          *Config
	core         *CoreManager
	agentVersion string

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

	// Seams (tests).
	dial           func(ctx context.Context) (pb.AgentChannel_OpenChannelClient, func(), error)
	backoffBase    time.Duration
	leaseEvery     time.Duration
	trafficEvery   time.Duration
	heartbeatEvery time.Duration
}

func NewAgent(cfg *Config, agentVersion string) *Agent {
	a := &Agent{
		cfg:            cfg,
		core:           NewCoreManager(),
		agentVersion:   agentVersion,
		lease:          newLeaseState(bootClock),
		backoffBase:    time.Second,
		leaseEvery:     5 * time.Second,
		trafficEvery:   10 * time.Second,
		heartbeatEvery: 15 * time.Second,
	}
	a.dial = a.dialPanel
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
	go a.leaseLoop(ctx)
	backoff := a.backoffBase
	for {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("channel closed", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if time.Since(start) > time.Minute {
			backoff = a.backoffBase
		} else {
			backoff *= 2
			if backoff > 30*a.backoffBase {
				backoff = 30 * a.backoffBase
			}
		}
	}
}

func (a *Agent) dialPanel(ctx context.Context) (pb.AgentChannel_OpenChannelClient, func(), error) {
	tlsCfg, err := a.tlsConfig()
	if err != nil {
		return nil, func() {}, err
	}
	conn, err := grpc.NewClient(
		a.cfg.PanelAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, func() {}, err
	}
	stream, err := pb.NewAgentChannelClient(conn).OpenChannel(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, func() {}, err
	}
	return stream, func() { _ = conn.Close() }, nil
}

// session runs one gRPC stream until it breaks. It returns only after every
// goroutine it started has exited — in particular the reader, which may be
// in the middle of a Rebuild: at most one handleDown runs at any time, and
// a dead stream's reader can never race the next stream's (F3).
func (a *Agent) session(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	stream, closeConn, err := a.dial(ctx)
	defer closeConn()
	if err != nil {
		return err
	}
	slog.Info("channel established", "panel", a.cfg.PanelAddr)

	sendCh := make(chan *pb.AgentUp, 256)
	done := make(chan error, 2)
	var wg sync.WaitGroup
	defer wg.Wait() // runs after cancel (defers are LIFO)
	defer cancel()

	// Writer: serializes all upstream messages onto the stream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-sendCh:
				if err := stream.Send(msg); err != nil {
					done <- err
					return
				}
			}
		}
	}()

	send := func(msg *pb.AgentUp) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case sendCh <- msg:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Hello (and any final counters still owed) before anything else. The
	// apply lock keeps a concurrent lease expiry from interleaving.
	a.applyMu.Lock()
	gen := a.attachStream(send)
	err = send(a.helloLocked())
	if err == nil {
		a.finals.flush(gen, send)
	}
	a.applyMu.Unlock()
	defer a.detachStream(gen)
	if err != nil {
		return err
	}

	wg.Add(3)
	go func() { defer wg.Done(); heartbeatLoop(ctx, a.heartbeatEvery, send, a.lease.remaining) }()
	go func() {
		defer wg.Done()
		trafficLoop(ctx, a.trafficEvery, a.core, send, func() { a.finals.confirm(gen, a.trafficEvery) })
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
			if err := a.handleDown(ctx, gen, send, in); err != nil {
				slog.Error("failed to handle panel message", "error", err)
			}
		}
	}()

	return <-done
}

func (a *Agent) attachStream(send func(*pb.AgentUp) error) uint64 {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	a.streamGen++
	a.curSend = send
	return a.streamGen
}

func (a *Agent) detachStream(gen uint64) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	if a.streamGen == gen {
		a.curSend = nil
	}
}

// current returns the live stream's generation and sender (nil if none).
func (a *Agent) current() (uint64, func(*pb.AgentUp) error) {
	a.streamMu.Lock()
	defer a.streamMu.Unlock()
	return a.streamGen, a.curSend
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
		Info: &pb.AgentInfo{
			AgentVersion: a.agentVersion,
			CoreVersion:  core.Version(),
			Os:           runtime.GOOS,
			Arch:         runtime.GOARCH,
		},
	}}}
}

var errStreamGone = errors.New("stream closed before the message was handled")

// handleDown applies one panel message. ctx is the stream's: once it is
// done nothing of the message may take effect (no Rebuild, no version
// change, no send), so a message from a dead stream can never be applied
// after the next stream's messages.
func (a *Agent) handleDown(ctx context.Context, gen uint64, send func(*pb.AgentUp) error, in *pb.PanelDown) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if ctx.Err() != nil {
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
	return a.sendAckLocked(send, snap.ConfigVersion, snap.UserVersion, reason, err)
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
	return a.sendAckLocked(send, target[0], target[1], pb.Ack_REASON_OK, nil)
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

func (a *Agent) tlsConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(a.cfg.Identity.CertPEM), []byte(a.cfg.Identity.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid identity keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(a.cfg.Identity.CAPEM)) {
		return nil, fmt.Errorf("cannot parse identity.ca_pem")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, nil
}

// finalQueue holds final counter reports of instances (or removed users)
// that must reach the panel. Accounting is idempotent (cumulative values per
// session), so a report is resent on every new stream until one stream has
// carried it and then stayed up for a full traffic interval.
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
		if send(&pb.AgentUp{Msg: &pb.AgentUp_Traffic{Traffic: it.report}}) != nil {
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

func (q *finalQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
