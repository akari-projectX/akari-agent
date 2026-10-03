package main

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/proxy/trojan"
	"google.golang.org/protobuf/proto"
)

// trojanModule: Trojan, account {"password"}.
type trojanModule struct{}

func (trojanModule) wire() string { return "trojan" }

func (m trojanModule) classify(_ string, msg proto.Message) (inboundKind, bool, error) {
	_, ok := msg.(*trojan.ServerConfig)
	return inboundKind{protocol: m.wire()}, ok, nil
}

func (trojanModule) account(accountJSON string, _ inboundKind) (proto.Message, error) {
	a := &trojan.Account{}
	if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
		return nil, fmt.Errorf("trojan account: %w", err)
	}
	return a, nil
}
