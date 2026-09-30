package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// Agent is the node-side supervisor: one persistent mTLS gRPC stream to the
// panel, an embedded xray-core, and periodic heartbeat/traffic reporting.
type Agent struct {
	cfg          *Config
	core         *CoreManager
	agentVersion string

	mu         sync.Mutex
	heldConfig uint64
	heldUser   uint64
}

func NewAgent(cfg *Config, agentVersion string) *Agent {
	return &Agent{
		cfg:          cfg,
		core:         NewCoreManager(),
		agentVersion: agentVersion,
	}
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

// Run keeps the channel alive for the process lifetime, reconnecting with
// capped exponential backoff.
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
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
			backoff = time.Second
		} else {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

// session runs one gRPC stream until it breaks.
func (a *Agent) session(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := grpc.NewClient(
		a.cfg.PanelAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(a.tlsConfig())),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentChannelClient(conn)
	stream, err := client.OpenChannel(ctx)
	if err != nil {
		return err
	}
	slog.Info("channel established", "panel", a.cfg.PanelAddr)

	sendCh := make(chan *pb.AgentUp, 256)
	done := make(chan error, 2)

	// Writer: serializes all upstream messages onto the stream. It exits on
	// the first Send error; session teardown cancels the context, which
	// unblocks it, so the channel is never closed while senders exist.
	go func() {
		for msg := range sendCh {
			if err := stream.Send(msg); err != nil {
				done <- err
				return
			}
		}
	}()

	send := func(msg *pb.AgentUp) error {
		select {
		case sendCh <- msg:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := send(a.hello()); err != nil {
		return err
	}

	go heartbeatLoop(ctx, send)
	go trafficLoop(ctx, a.core, send)

	// Reader: applies panel-pushed state.
	go func() {
		for {
			in, err := stream.Recv()
			if err != nil {
				done <- err
				return
			}
			if err := a.handleDown(send, in); err != nil {
				slog.Error("failed to handle panel message", "error", err)
			}
		}
	}()

	return <-done
}

// hello describes the agent's current state: the session its traffic
// counters belong to and the versions it holds. Sent first on every stream
// and again after every Rebuild (new session).
func (a *Agent) hello() *pb.AgentUp {
	configVersion, userVersion := a.versions()
	return &pb.AgentUp{Msg: &pb.AgentUp_Hello{Hello: &pb.Hello{
		SessionId:     a.core.SessionID(),
		ConfigVersion: configVersion,
		UserVersion:   userVersion,
		Info: &pb.AgentInfo{
			AgentVersion: a.agentVersion,
			CoreVersion:  core.Version(),
			Os:           runtime.GOOS,
			Arch:         runtime.GOARCH,
		},
	}}}
}

func (a *Agent) handleDown(send func(*pb.AgentUp) error, in *pb.PanelDown) error {
	switch msg := in.Msg.(type) {
	case *pb.PanelDown_Snapshot:
		snap := msg.Snapshot
		slog.Info("applying config snapshot",
			"config_version", snap.ConfigVersion,
			"user_version", snap.UserVersion,
			"users", len(snap.Users))
		final, err := a.core.Rebuild(snap.InboundsJson, snap.Users)
		// Report the old instance's last counters (old session) so the
		// traffic since the previous 10s tick is not lost.
		if final != nil {
			if serr := send(&pb.AgentUp{Msg: &pb.AgentUp_Traffic{Traffic: final}}); serr != nil {
				return serr
			}
		}
		// Only a clean apply moves the held versions. On failure the agent
		// keeps claiming its previous versions (Hello), and the Ack reports
		// the ATTEMPTED versions with ok=false, so the panel can never
		// mistake a failed apply for convergence.
		if err == nil {
			a.setVersions(snap.ConfigVersion, snap.UserVersion)
		}
		// Counters restarted under a new session: announce it.
		if serr := send(a.hello()); serr != nil {
			return serr
		}
		return sendAck(send, snap.ConfigVersion, snap.UserVersion, err)

	case *pb.PanelDown_Delta:
		delta := msg.Delta
		slog.Info("applying user delta",
			"user_version", delta.UserVersion,
			"ops", len(delta.Ops))
		err := a.core.ApplyDelta(delta.Ops)
		curConfig, _ := a.versions()
		if err == nil {
			a.setVersions(curConfig, delta.UserVersion)
		}
		return sendAck(send, curConfig, delta.UserVersion, err)

	case *pb.PanelDown_Noop:
		return nil
	case nil:
		return nil
	default:
		slog.Warn("unknown panel message type")
		return nil
	}
}

func sendAck(send func(*pb.AgentUp) error, configVersion, userVersion uint64, err error) error {
	ack := &pb.Ack{ConfigVersion: configVersion, UserVersion: userVersion, Ok: err == nil}
	if err != nil {
		ack.Error = err.Error()
		slog.Error("sending failure ack", "error", err)
	}
	return send(&pb.AgentUp{Msg: &pb.AgentUp_Ack{Ack: ack}})
}

func (a *Agent) tlsConfig() *tls.Config {
	cert, err := tls.X509KeyPair([]byte(a.cfg.Identity.CertPEM), []byte(a.cfg.Identity.KeyPEM))
	if err != nil {
		panic("agent: invalid identity keypair: " + err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(a.cfg.Identity.CAPEM)) {
		panic("agent: cannot parse identity.ca_pem")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   a.cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
}
