package main

import (
	"fmt"

	"github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"google.golang.org/protobuf/proto"
)

// hysteria2Module: Hysteria 2 (xray `hysteria` proxy + `hysteria`
// transport), account {"auth"}.
type hysteria2Module struct{}

func (hysteria2Module) wire() string { return "hysteria" }

func (m hysteria2Module) classify(_ string, msg proto.Message) (inboundKind, bool, error) {
	_, ok := msg.(*hysteria.ServerConfig)
	return inboundKind{protocol: m.wire()}, ok, nil
}

// hysteriaAuthMin: the validator keys users by auth: an empty or short one
// would be guessable or collide (manifest credential `auth` min_len).
var hysteriaAuthMin = func() int {
	if c := protocolSpec("hysteria").credential("auth"); c != nil && c.MinLen > 0 {
		return c.MinLen
	}
	return 16
}()

func (hysteria2Module) account(accountJSON string, _ inboundKind) (proto.Message, error) {
	var a struct {
		Auth string `json:"auth"`
	}
	if err := decodeStrict(accountJSON, &a); err != nil {
		return nil, fmt.Errorf("hysteria account: %w", err)
	}
	if len(a.Auth) < hysteriaAuthMin {
		return nil, fmt.Errorf("hysteria account: auth must be at least %d characters", hysteriaAuthMin)
	}
	return &hyaccount.Account{Auth: a.Auth}, nil
}
