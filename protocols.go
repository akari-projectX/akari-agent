package main

// Per-protocol handling of panel-managed inbounds (W8; W26: one module per
// protocol behind protocolModule, the rules from proto/protocols.toml):
// which inbounds take dynamic users, how a panel account becomes an xray
// user, and protocol specifics (Shadowsocks 2022 multi-user, tombstones).
//
// Managed protocols (the panel issues credentials, the xray "email" is the
// panel user id, the gate admits by *MemoryUser); wire name = manifest
// `wire`, the agent contract's InboundUser.protocol:
//
//	vless       account {"id","flow"}       proto_vless.go
//	vmess       account {"id"}              proto_vmess.go
//	trojan      account {"password"}        proto_trojan.go
//	shadowsocks account {"password"}        proto_ss2022.go (2022 multi-user)
//	hysteria    account {"auth"}            proto_hysteria2.go (Hysteria 2)
//
// Adding a protocol: a [[protocol]] in the panel's manifest (synced here),
// a module file implementing protocolModule (and its canary builder in
// rt_matrix_test.go), registered in protocolModules. TestModulesMatchManifest
// fails until both sides agree.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"

	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
)

// inboundKind is what xray built for one inbound tag: the managed protocol
// (wire name; "" = an inbound without panel-managed users) and, for
// Shadowsocks 2022, the user key length its method needs.
type inboundKind struct {
	protocol string
	ssKeyLen int
}

// protocolModule is one managed protocol on the xray kernel.
type protocolModule interface {
	// wire: the protocol's agent-contract name (manifest `wire`).
	wire() string
	// classify: is msg (an inbound's proxy settings as xray built them)
	// this protocol, and its kind. Authoritative: after xray's own parse.
	classify(tag string, msg proto.Message) (inboundKind, bool, error)
	// account: the xray account for a panel account_json on an inbound of
	// this kind (the module's credential checks; kind.protocol == wire()).
	account(accountJSON string, kind inboundKind) (proto.Message, error)
}

// protocolModules: the registry, in manifest order.
var protocolModules = []protocolModule{
	vlessModule{}, vmessModule{}, trojanModule{}, ss2022Module{}, hysteria2Module{},
}

var modulesByWire = func() map[string]protocolModule {
	out := make(map[string]protocolModule, len(protocolModules))
	for _, mod := range protocolModules {
		out[mod.wire()] = mod
	}
	return out
}()

// protocolSpec: the manifest entry of a module (the registry and the
// manifest agree: TestModulesMatchManifest).
func protocolSpec(wire string) *manifestProtocol {
	if p := manifest.protocolByWire(wire); p != nil {
		return p
	}
	return &manifestProtocol{Wire: wire}
}

// inboundKinds classifies every inbound of a built config by the proxy
// settings xray produced (authoritative: after xray's own parse).
func inboundKinds(cfg *core.Config) (map[string]inboundKind, error) {
	kinds := make(map[string]inboundKind, len(cfg.Inbound))
	for _, in := range cfg.Inbound {
		if in.ProxySettings == nil {
			continue
		}
		msg, err := in.ProxySettings.GetInstance()
		if err != nil {
			return nil, fmt.Errorf("inbound %q: proxy settings: %w", in.Tag, err)
		}
		var k inboundKind
		for _, mod := range protocolModules {
			mk, ok, err := mod.classify(in.Tag, msg)
			if err != nil {
				return nil, err
			}
			if ok {
				k = mk
				break
			}
		}
		kinds[in.Tag] = k
	}
	return kinds, nil
}

// decodeStrict unmarshals one JSON object refusing unknown fields.
func decodeStrict(accountJSON string, v any) error {
	dec := json.NewDecoder(strings.NewReader(accountJSON))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// buildUser constructs an xray user whose "email" field carries the panel
// user ID: that is the key for per-user traffic counters and for the gate.
// kind is what the target inbound really is: a credential of another
// protocol is refused here (xray's validators type-assert the account and
// would panic on a mismatch).
func buildUser(protocolName, accountJSON, userID string, kind inboundKind) (*protocol.User, error) {
	if kind.protocol == "" {
		return nil, fmt.Errorf("inbound takes no managed users")
	}
	if protocolName != kind.protocol {
		return nil, fmt.Errorf("credential is %s, inbound is %s", protocolName, kind.protocol)
	}
	mod, ok := modulesByWire[protocolName]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol %q", protocolName)
	}
	account, err := mod.account(accountJSON, kind)
	if err != nil {
		return nil, err
	}
	return &protocol.User{
		Level:   0,
		Email:   userID,
		Account: commonserial.ToTypedMessage(account),
	}, nil
}

// shrinkUnsafe: a user must never leave the user table of a running
// inbound of this kind (manifest `shrink_unsafe`: Shadowsocks 2022, whose
// xray multi-user inbound swap-deletes; see proto_ss2022.go). Removals
// there are tombstones; rotations need a rebuild (BASE_MISMATCH).
func shrinkUnsafe(k inboundKind) bool {
	return k.protocol != "" && protocolSpec(k.protocol).ShrinkUnsafe
}
