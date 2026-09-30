package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/transport/internet"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"

	"akari/agent/pb"
)

// The proxyman handler exposes the running proxy; the protocol inbounds
// (vless/vmess Handler, trojan Server) own the user store.
type proxyExposer interface {
	GetInbound() proxy.Inbound
}

type userManager interface {
	AddUser(ctx context.Context, u *protocol.MemoryUser) error
	RemoveUser(ctx context.Context, email string) error
}

func userStore(handler inbound.Handler) (userManager, error) {
	exposer, ok := handler.(proxyExposer)
	if !ok {
		return nil, fmt.Errorf("handler does not expose its proxy")
	}
	store, ok := exposer.GetInbound().(userManager)
	if !ok {
		return nil, fmt.Errorf("proxy inbound does not support dynamic users")
	}
	return store, nil
}

// CoreManager owns the embedded xray-core instance. The agent is a
// supervisor: it (re)builds the instance from panel-pushed snapshots and
// applies per-user changes in place, without restarting the process.
type CoreManager struct {
	mu          sync.Mutex
	instance    *core.Instance
	inboundTags []string
	// sessionID names the lifetime of the current traffic counters. It is
	// only changed under mu, together with the instance, so a
	// TrafficSnapshot can never pair one instance's counters with another
	// instance's session (the panel bills by (node, user, session)).
	sessionID string
	emailsMu  sync.RWMutex
	emails    map[string]struct{}
	// onStart is a test seam, called under mu right after a new instance
	// is installed. Always nil in production.
	onStart func(*core.Instance)
}

func NewCoreManager() *CoreManager {
	return &CoreManager{emails: make(map[string]struct{}), sessionID: newSessionID()}
}

// SessionID returns the session the current counters belong to.
func (m *CoreManager) SessionID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionID
}

// Rebuild stops the current instance (if any) and starts a new one from the
// panel's desired state. Traffic counters reset here, so a fresh session id
// is minted under the same lock. The old instance's final counters (tagged
// with the old session) are returned so the caller can report them instead
// of losing up to one reporting interval of traffic; nil if there were none.
func (m *CoreManager) Rebuild(inboundsJSON string, users []*pb.UserOp) (*pb.TrafficReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var final *pb.TrafficReport
	if m.instance != nil {
		if counters := m.countersLocked(); len(counters) > 0 {
			final = &pb.TrafficReport{Users: counters, SessionId: m.sessionID}
		}
		_ = m.instance.Close()
		m.instance = nil
		m.inboundTags = nil
	}
	// Counters restart with whatever instance comes next (or none).
	m.sessionID = newSessionID()

	inst, tags, err := newInstance(inboundsJSON)
	if err != nil {
		return final, err
	}

	m.instance = inst
	m.inboundTags = tags
	if m.onStart != nil {
		m.onStart(inst)
	}
	m.emailsMu.Lock()
	m.emails = make(map[string]struct{})
	m.emailsMu.Unlock()

	var firstErr error
	for _, op := range users {
		if err := m.applyOp(op); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return final, firstErr
}

// ApplyDelta applies incremental user ops to the running instance.
func (m *CoreManager) ApplyDelta(ops []*pb.UserOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return fmt.Errorf("core not started")
	}
	var firstErr error
	for _, op := range ops {
		if err := m.applyOp(op); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *CoreManager) applyOp(op *pb.UserOp) error {
	switch op.GetOp() {
	case pb.UserOp_ADD:
		m.emailsMu.Lock()
		m.emails[op.UserId] = struct{}{}
		m.emailsMu.Unlock()
		for _, iu := range op.InboundUsers {
			if err := m.addUser(iu.InboundTag, iu.Protocol, iu.AccountJson, op.UserId); err != nil {
				return err
			}
		}
	case pb.UserOp_REMOVE:
		m.emailsMu.Lock()
		delete(m.emails, op.UserId)
		m.emailsMu.Unlock()
		for _, tag := range m.inboundTags {
			// The user may not exist on every inbound; ignore not-found.
			_ = m.removeUser(tag, op.UserId)
		}
	default:
		return fmt.Errorf("unknown user op %d", op.GetOp())
	}
	return nil
}

func (m *CoreManager) manager() inbound.Manager {
	return m.instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
}

func (m *CoreManager) addUser(tag, protocolName, accountJSON, userID string) error {
	user, err := buildUser(protocolName, accountJSON, userID)
	if err != nil {
		return err
	}
	memoryUser, err := user.ToMemoryUser()
	if err != nil {
		return fmt.Errorf("materialize user: %w", err)
	}
	handler, err := m.manager().GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("inbound %q: %w", tag, err)
	}
	store, err := userStore(handler)
	if err != nil {
		return fmt.Errorf("inbound %q: %w", tag, err)
	}
	// Idempotent: a stale snapshot replay must not fail on "already exists".
	_ = store.RemoveUser(context.Background(), userID)
	if err := store.AddUser(context.Background(), memoryUser); err != nil {
		return fmt.Errorf("add user to inbound %q: %w", tag, err)
	}
	return nil
}

func (m *CoreManager) removeUser(tag, userID string) error {
	handler, err := m.manager().GetHandler(context.Background(), tag)
	if err != nil {
		return err
	}
	store, err := userStore(handler)
	if err != nil {
		return err
	}
	return store.RemoveUser(context.Background(), userID)
}

// buildUser constructs an xray user whose "email" field carries the panel
// user id — the stats counter namespace (user>>>{email}>>>traffic>>>*) is
// keyed on it, which keeps the panel <-> core identity mapping trivial.
func buildUser(protocolName, accountJSON, userID string) (*protocol.User, error) {
	var account proto.Message
	switch protocolName {
	case "vless":
		a := &vless.Account{}
		if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
			return nil, fmt.Errorf("vless account: %w", err)
		}
		account = a
	case "vmess":
		a := &vmess.Account{}
		if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
			return nil, fmt.Errorf("vmess account: %w", err)
		}
		account = a
	case "trojan":
		a := &trojan.Account{}
		if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
			return nil, fmt.Errorf("trojan account: %w", err)
		}
		account = a
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocolName)
	}
	if account == nil {
		return nil, fmt.Errorf("empty account for protocol %q", protocolName)
	}
	return &protocol.User{
		Level:   0,
		Email:   userID,
		Account: commonserial.ToTypedMessage(account),
	}, nil
}

// TrafficSnapshot returns the current session id together with the
// cumulative per-user counters of the instance that session names. Both are
// read under mu, so a concurrent Rebuild cannot split them.
func (m *CoreManager) TrafficSnapshot() *pb.TrafficReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil
	}
	return &pb.TrafficReport{Users: m.countersLocked(), SessionId: m.sessionID}
}

// countersLocked reads per-user counters of m.instance. Caller holds mu.
func (m *CoreManager) countersLocked() []*pb.UserTraffic {
	sm, ok := m.instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return nil
	}

	m.emailsMu.RLock()
	emails := make([]string, 0, len(m.emails))
	for e := range m.emails {
		emails = append(emails, e)
	}
	m.emailsMu.RUnlock()

	var out []*pb.UserTraffic
	for _, email := range emails {
		up := counterValue(sm, "user>>>"+email+">>>traffic>>>uplink")
		down := counterValue(sm, "user>>>"+email+">>>traffic>>>downlink")
		if up == 0 && down == 0 {
			continue
		}
		out = append(out, &pb.UserTraffic{
			UserId:    email,
			UpBytes:   uint64(up),
			DownBytes: uint64(down),
		})
	}
	return out
}

func counterValue(sm stats.Manager, name string) int64 {
	c := sm.GetCounter(name)
	if c == nil {
		return 0
	}
	return c.Value()
}

func newInstance(inboundsJSON string) (*core.Instance, []string, error) {
	var inbounds []json.RawMessage
	if err := json.Unmarshal([]byte(inboundsJSON), &inbounds); err != nil {
		return nil, nil, fmt.Errorf("parse inbounds: %w", err)
	}
	if len(inbounds) == 0 {
		inbounds = []json.RawMessage{}
	}

	full := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"protocol": "freedom"},
		},
		// Per-user traffic counters live behind these policy switches.
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": map[string]any{
				"statsInboundUplink":   true,
				"statsInboundDownlink": true,
			},
		},
		"stats": map[string]any{},
	}
	b, err := json.Marshal(full)
	if err != nil {
		return nil, nil, err
	}

	jsonConfig, err := confserial.DecodeJSONConfig(bytes.NewReader(b))
	if err != nil {
		return nil, nil, fmt.Errorf("decode xray config: %w", err)
	}
	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("build xray config: %w", err)
	}
	inst, err := core.New(pbConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("build xray instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, nil, fmt.Errorf("start xray instance: %w", err)
	}

	tags := make([]string, 0, len(inbounds))
	for _, raw := range inbounds {
		var probe struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.Tag != "" {
			tags = append(tags, probe.Tag)
		}
	}
	return inst, tags, nil
}
