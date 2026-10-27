//go:build soak

// Soak test (build tags canary + soak, `make soak`): shared definitions of
// the parent harness (soak_test.go: the real Agent against an in-process
// fake panel) and the client process (soak_client_test.go: real xray
// clients that load the agent). Never part of normal CI.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// soakKind is one inbound of the soak node.
type soakKind struct {
	tag      string
	proto    string // InboundUser.protocol (wire name)
	relay    bool   // a relay-derived inbound: its users are "<id>#1"
	innerTLS bool   // the proxied payload is TLS 1.3 (Vision)
}

var soakKinds = []soakKind{
	{tag: "vision", proto: "vless", innerTLS: true}, // VLESS + REALITY + Vision
	{tag: "vmess", proto: "vmess"},
	{tag: "trojan", proto: "trojan"}, // over TLS
	{tag: "ss", proto: "shadowsocks"},
	{tag: "hy2", proto: "hysteria"},
	{tag: "e1", proto: "vless", relay: true}, // derived inbound of relay entrance 1
}

func soakKindOf(tag string) soakKind {
	for _, k := range soakKinds {
		if k.tag == tag {
			return k
		}
	}
	panic("unknown soak inbound " + tag)
}

const soakSSMethod = "2022-blake3-aes-128-gcm"

// soakCred is one user's credential on one inbound.
type soakCred struct {
	account string // UserOp account_json
	secret  string // the client side's id / password / key / auth
}

// soakCredential derives the credential of (user, inbound) in generation
// gen: a rotation is gen+1.
func soakCredential(k soakKind, user string, gen int) soakCred {
	h := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d", user, k.tag, gen))
	switch k.proto {
	case "vless", "vmess":
		b := h[:16]
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		id := uuid.UUID(b).String()
		if k.proto == "vless" {
			flow := ""
			if k.innerTLS {
				flow = "xtls-rprx-vision"
			}
			return soakCred{account: fmt.Sprintf(`{"flow":%q,"id":%q}`, flow, id), secret: id}
		}
		return soakCred{account: fmt.Sprintf(`{"id":%q}`, id), secret: id}
	case "trojan":
		pw := "soak-" + hex.EncodeToString(h[:12])
		return soakCred{account: fmt.Sprintf(`{"password":%q}`, pw), secret: pw}
	case "shadowsocks":
		key := base64.StdEncoding.EncodeToString(h[:16])
		return soakCred{account: fmt.Sprintf(`{"password":%q}`, key), secret: key}
	case "hysteria":
		auth := hex.EncodeToString(h[:16])
		return soakCred{account: fmt.Sprintf(`{"auth":%q}`, auth), secret: auth}
	}
	panic("unknown protocol " + k.proto)
}

// soakEnv: what both sides need to agree on.
type soakEnv struct {
	Pin      string `json:"pin"`
	RealPub  string `json:"real_pub"`
	SSPSK    string `json:"ss_psk"`
	TLSEcho  int    `json:"-"`
	Ports    map[string]int
	RealDest int `json:"-"`
}

// soakInbounds renders the node's inbounds_json.
func soakInbounds(e *matrixEnv, env *soakEnv) string {
	var out []string
	for _, k := range soakKinds {
		port := env.Ports[k.tag]
		head := fmt.Sprintf(`"tag":%q,"listen":"127.0.0.1","port":%d,`, k.tag, port)
		var body string
		switch k.tag {
		case "vision":
			body = `"protocol":"vless","settings":{"clients":[],"decryption":"none","flow":"xtls-rprx-vision"},"streamSettings":{"network":"tcp",` + e.serverReality(env.RealDest) + `}`
		case "vmess":
			body = `"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp"}`
		case "trojan":
			body = `"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"tcp",` + e.serverTLS() + `}`
		case "ss":
			body = fmt.Sprintf(`"protocol":"shadowsocks","settings":{"method":%q,"password":%q,"clients":[],"network":"tcp,udp"}`, soakSSMethod, env.SSPSK)
		case "hy2":
			body = `"protocol":"hysteria","settings":{"version":2,"clients":[]},"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2},` + e.serverTLS("h3") + `}`
		case "e1":
			body = `"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp"}`
		}
		out = append(out, "{"+head+body+"}")
	}
	return "[" + joinComma(out) + "]"
}

func joinComma(s []string) string {
	r := ""
	for i, x := range s {
		if i > 0 {
			r += ","
		}
		r += x
	}
	return r
}

// soakOutbound is the xray client outbound for (inbound, credential).
func soakOutbound(e *matrixEnv, env *soakEnv, k soakKind, c soakCred) map[string]any {
	port := env.Ports[k.tag]
	switch k.tag {
	case "vision":
		return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": c.secret, "flow": "xtls-rprx-vision", "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": e.clientReality()}}
	case "vmess":
		return map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": c.secret, "security": "auto"}}}}},
			"streamSettings": map[string]any{"network": "tcp"}}
	case "trojan":
		return map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "password": c.secret}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": e.clientTLS()}}
	case "ss":
		return map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "method": soakSSMethod, "password": env.SSPSK + ":" + c.secret}}}}
	case "hy2":
		return map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "127.0.0.1", "port": port},
			"streamSettings": map[string]any{"network": "hysteria", "security": "tls", "tlsSettings": e.clientTLS("h3"),
				"hysteriaSettings": map[string]any{"version": 2, "auth": c.secret}}}
	case "e1":
		return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": c.secret, "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "tcp"}}
	}
	panic("unknown inbound " + k.tag)
}
