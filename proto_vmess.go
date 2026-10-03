package main

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	"google.golang.org/protobuf/proto"
)

// vmessModule: VMess, account {"id"} (alterId 0, security auto).
type vmessModule struct{}

func (vmessModule) wire() string { return "vmess" }

func (m vmessModule) classify(_ string, msg proto.Message) (inboundKind, bool, error) {
	_, ok := msg.(*vmessin.Config)
	return inboundKind{protocol: m.wire()}, ok, nil
}

func (vmessModule) account(accountJSON string, _ inboundKind) (proto.Message, error) {
	a := &vmess.Account{}
	if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
		return nil, fmt.Errorf("vmess account: %w", err)
	}
	return a, nil
}
