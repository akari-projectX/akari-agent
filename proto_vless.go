package main

import (
	"encoding/json"
	"fmt"

	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"google.golang.org/protobuf/proto"
)

// vlessModule: VLESS, account {"id","flow"}. The flow follows the inbound
// (the panel refits credentials when it changes); allowed flows are the
// manifest's (`flow` option of vless), each of which xray must implement
// (TestManifestFlowsAreXrayFlows).
type vlessModule struct{}

func (vlessModule) wire() string { return "vless" }

func (m vlessModule) classify(_ string, msg proto.Message) (inboundKind, bool, error) {
	_, ok := msg.(*vlessin.Config)
	return inboundKind{protocol: m.wire()}, ok, nil
}

// vlessFlows: the flows an account may carry.
var vlessFlows = func() map[string]bool {
	out := map[string]bool{}
	if o := protocolSpec("vless").option("flow"); o != nil {
		for _, v := range o.Values {
			out[v] = true
		}
	}
	return out
}()

func (vlessModule) account(accountJSON string, _ inboundKind) (proto.Message, error) {
	a := &vless.Account{}
	if err := json.Unmarshal([]byte(accountJSON), a); err != nil {
		return nil, fmt.Errorf("vless account: %w", err)
	}
	if !vlessFlows[a.Flow] {
		return nil, fmt.Errorf("vless account: unsupported flow %q", a.Flow)
	}
	return a, nil
}
