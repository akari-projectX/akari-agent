package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	commonserial "github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"google.golang.org/protobuf/proto"
)

// ss2022Module: Shadowsocks 2022, multi-user only, account {"password"}
// (standard base64 user key of the method's key length).
//
// Tombstones (manifest `shrink_unsafe`, protocols.go shrinkUnsafe): a user
// must never leave the user table of a running xray multi-user
// Shadowsocks 2022 inbound. MultiUserInbound.RemoveUser
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
type ss2022Module struct{}

func (ss2022Module) wire() string { return "shadowsocks" }

// ss2022KeyLen: multi-user Shadowsocks 2022 methods and their key length in
// bytes (manifest: the ss2022 `method` option and its key_len). xray's
// multi-user server only implements the AES methods
// (2022-blake3-chacha20-poly1305 is single-user only).
var ss2022KeyLen = func() map[string]int {
	if o := protocolSpec("shadowsocks").option("method"); o != nil {
		return o.keyLens()
	}
	return map[string]int{}
}()

func (m ss2022Module) classify(tag string, msg proto.Message) (inboundKind, bool, error) {
	c, ok := msg.(*ss2022.MultiUserServerConfig)
	if !ok {
		return inboundKind{}, false, nil
	}
	n, ok := ss2022KeyLen[c.GetMethod()]
	if !ok {
		return inboundKind{}, false, fmt.Errorf("inbound %q: shadowsocks method %q has no multi-user server", tag, c.GetMethod())
	}
	return inboundKind{protocol: m.wire(), ssKeyLen: n}, true, nil
}

func (ss2022Module) account(accountJSON string, kind inboundKind) (proto.Message, error) {
	var a struct {
		Password string `json:"password"`
	}
	if err := decodeStrict(accountJSON, &a); err != nil {
		return nil, fmt.Errorf("shadowsocks account: %w", err)
	}
	if err := checkSSKey(a.Password, kind.ssKeyLen); err != nil {
		return nil, fmt.Errorf("shadowsocks account: %w", err)
	}
	return &ss2022.Account{Key: a.Password}, nil
}

// inboundJSON is one inbound as xray's own config structs read it (Go
// encoding/json into a struct: keys match case-insensitively and the LAST
// matching member wins). multiUserShadowsocks must see exactly the tag and
// settings xray saw: a map lookup that preferred the exact-case key would
// pick another member of {"tag":"a","TAG":"b"} than xray does, and the
// inbound xray built as "b" would stay a single-user server.
type inboundJSON struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
}

// ssSettingsJSON: the "clients" member of Shadowsocks settings, as xray's
// ShadowsocksServerConfig reads it.
type ssSettingsJSON struct {
	Clients json.RawMessage `json:"clients"`
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
		var in inboundJSON
		if err := json.Unmarshal(raw, &in); err != nil {
			continue // xray's own parse already accepted or refused it
		}
		if !strings.EqualFold(in.Protocol, "shadowsocks") {
			continue
		}
		var settings ssSettingsJSON
		if len(in.Settings) > 0 {
			_ = json.Unmarshal(in.Settings, &settings)
		}
		if len(settings.Clients) > 0 && !bytes.Equal(bytes.TrimSpace(settings.Clients), []byte("null")) {
			managed[in.Tag] = true
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
