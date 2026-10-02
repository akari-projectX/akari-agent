package main

// Per-protocol handling of panel-managed inbounds (W8): which inbounds take
// dynamic users, how a panel account becomes an xray user, and the
// Shadowsocks 2022 multi-user specifics.
//
// Managed protocols (the panel issues credentials, the xray "email" is the
// panel user id, the gate admits by *MemoryUser):
//
//	vless       account {"id","flow"}       flow "" or xtls-rprx-vision
//	vmess       account {"id"}
//	trojan      account {"password"}
//	shadowsocks account {"password"}        2022-blake3-aes-{128,256}-gcm
//	                                        multi-user only; base64 user key
//	                                        of the method's key length
//	hysteria    account {"auth"}            Hysteria 2 (xray `hysteria`
//	                                        proxy + `hysteria` transport)

import (
	"bytes"
	"encoding/base64"
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

	"github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
)

// inboundKind is what xray built for one inbound tag: the managed protocol
// name ("" = an inbound without panel-managed users) and, for Shadowsocks
// 2022, the user key length its method needs.
type inboundKind struct {
	protocol string
	ssKeyLen int
}

// ss2022KeyLen: multi-user Shadowsocks 2022 methods xray supports, and
// their key length in bytes. xray's multi-user server only implements the
// AES methods (2022-blake3-chacha20-poly1305 is single-user only).
var ss2022KeyLen = map[string]int{
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
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
		switch c := msg.(type) {
		case *vlessin.Config:
			k.protocol = "vless"
		case *vmessin.Config:
			k.protocol = "vmess"
		case *trojan.ServerConfig:
			k.protocol = "trojan"
		case *hysteria.ServerConfig:
			k.protocol = "hysteria"
		case *ss2022.MultiUserServerConfig:
			n, ok := ss2022KeyLen[c.GetMethod()]
			if !ok {
				return nil, fmt.Errorf("inbound %q: shadowsocks method %q has no multi-user server", in.Tag, c.GetMethod())
			}
			k = inboundKind{protocol: "shadowsocks", ssKeyLen: n}
		}
		kinds[in.Tag] = k
	}
	return kinds, nil
}

// jsonField returns obj's value for key the way Go's encoding/json (and so
// xray) matches it: case-insensitively. ok=false when absent.
func jsonField(obj map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// multiUserShadowsocks rewrites, in the built config, every Shadowsocks
// 2022 inbound whose JSON settings carry a "clients" array (even an empty
// one: users are added later through the user manager) into xray's
// multi-user server. Stock xray only builds the multi-user server when the
// list is non-empty and otherwise makes a single-user server keyed by the
// inbound password: one shared credential, no user identity, nothing for
// the gate to revoke. Without "clients" the inbound stays as xray built it
// (no panel-managed users). The server PSK is checked here (base64, the
// method's key length) so a bad PSK fails the apply, not the first client.
func multiUserShadowsocks(inbounds []json.RawMessage, cfg *core.Config) error {
	managed := map[string]bool{}
	for _, raw := range inbounds {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue // xray's own parse already accepted or refused it
		}
		var tag, proto string
		if v, ok := jsonField(obj, "tag"); ok {
			_ = json.Unmarshal(v, &tag)
		}
		if v, ok := jsonField(obj, "protocol"); ok {
			_ = json.Unmarshal(v, &proto)
		}
		if !strings.EqualFold(proto, "shadowsocks") {
			continue
		}
		var settings map[string]json.RawMessage
		if v, ok := jsonField(obj, "settings"); ok {
			_ = json.Unmarshal(v, &settings)
		}
		if v, ok := jsonField(settings, "clients"); ok && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			managed[tag] = true
		}
	}
	for _, in := range cfg.Inbound {
		if !managed[in.Tag] || in.ProxySettings == nil {
			continue
		}
		msg, err := in.ProxySettings.GetInstance()
		if err != nil {
			return fmt.Errorf("inbound %q: proxy settings: %w", in.Tag, err)
		}
		var method, key string
		var multi *ss2022.MultiUserServerConfig
		switch c := msg.(type) {
		case *ss2022.ServerConfig: // empty client list
			method, key = c.GetMethod(), c.GetKey()
			multi = &ss2022.MultiUserServerConfig{Method: method, Key: key, Network: c.GetNetwork()}
		case *ss2022.MultiUserServerConfig:
			method, key = c.GetMethod(), c.GetKey()
		default:
			return fmt.Errorf("inbound %q: shadowsocks with clients must use a 2022-blake3-aes-*-gcm method", in.Tag)
		}
		n, ok := ss2022KeyLen[method]
		if !ok {
			return fmt.Errorf("inbound %q: shadowsocks method %q has no multi-user server (use 2022-blake3-aes-128-gcm or -256-gcm)", in.Tag, method)
		}
		if err := checkSSKey(key, n); err != nil {
			return fmt.Errorf("inbound %q: server password: %w", in.Tag, err)
		}
		if multi != nil {
			in.ProxySettings = commonserial.ToTypedMessage(multi)
		}
	}
	return nil
}

// checkSSKey: standard base64 of exactly n bytes. sing-shadowsocks would
// stretch longer keys and reject shorter ones; worse, xray's multi-user
// AddUser ignores the error of its user-table update, so one bad key would
// silently freeze the table. Only exact keys get that far.
func checkSSKey(key string, n int) error {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("key is not standard base64")
	}
	if len(b) != n {
		return fmt.Errorf("key is %d bytes, the method needs %d", len(b), n)
	}
	return nil
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
	var account proto.Message
	switch protocolName {
	case "vless":
		a := &vless.Account{}
		if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
			return nil, fmt.Errorf("vless account: %w", err)
		}
		switch a.Flow {
		case "", vless.XRV:
		default:
			return nil, fmt.Errorf("vless account: unsupported flow %q", a.Flow)
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
	case "shadowsocks":
		var a struct {
			Password string `json:"password"`
		}
		if err := decodeStrict(accountJSON, &a); err != nil {
			return nil, fmt.Errorf("shadowsocks account: %w", err)
		}
		if err := checkSSKey(a.Password, kind.ssKeyLen); err != nil {
			return nil, fmt.Errorf("shadowsocks account: %w", err)
		}
		account = &ss2022.Account{Key: a.Password}
	case "hysteria":
		var a struct {
			Auth string `json:"auth"`
		}
		if err := decodeStrict(accountJSON, &a); err != nil {
			return nil, fmt.Errorf("hysteria account: %w", err)
		}
		// The validator keys users by auth: an empty or short one would be
		// guessable or collide.
		if len(a.Auth) < 16 {
			return nil, fmt.Errorf("hysteria account: auth must be at least 16 characters")
		}
		account = &hyaccount.Account{Auth: a.Auth}
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocolName)
	}
	return &protocol.User{
		Level:   0,
		Email:   userID,
		Account: commonserial.ToTypedMessage(account),
	}, nil
}

// shrinkUnsafe: a user must never leave the user table of a running xray
// multi-user Shadowsocks 2022 inbound. MultiUserInbound.RemoveUser
// swap-deletes from the slice the service's user indexes point into, and
// the connection path reads `users[index]` without a lock after a handshake
// the client can stall: a pending handshake of the removed user would then
// run as whichever user moved into its slot (admitted by the gate under
// that user, billed to them), or index past the end and panic the agent.
//
// So on these inbounds (W9) the agent never calls RemoveUser. A removal
// revokes the user in the gate only and leaves the credential in the table
// as a tombstone: indices never move, an in-flight or new handshake with
// that key resolves to the removed user's own *MemoryUser, which the gate
// refuses. Re-adding the SAME credential revives the tombstone (the gate
// admits that pointer again; xray is not touched). xray's AddUser refuses a
// duplicate email, so a different credential for a user the table holds
// (rotation, re-add with a new key) needs a new instance: such deltas are
// refused (BASE_MISMATCH) and the panel sends a Snapshot, which also
// compacts. Tombstones are bounded (maxTombstones); a removal past the
// bound is refused the same way. Tombstones are not "applied": they are
// outside the state hash and the user count. Additions append and are safe.
func shrinkUnsafe(k inboundKind) bool { return k.protocol == "shadowsocks" }
