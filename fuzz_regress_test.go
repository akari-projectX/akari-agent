package main

// Regression tests for the bugs the W13 fuzz targets found (fuzz_test.go).

import (
	"encoding/json"
	"strings"
	"testing"

	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// xray reads {"tag":"a","TAG":"b"} as tag "b" (case-insensitive, last
// member wins). The SS2022 multi-user rewrite must see the same tag, or
// "b" stays a single-user server keyed by the shared PSK.
func TestSSMultiUserFollowsXrayKeyMatching(t *testing.T) {
	in := []json.RawMessage{json.RawMessage(`{"tag":"a","TAG":"b","port":8388,"Protocol":"shadowsocks",` +
		`"settings":{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","clients":[]},` +
		`"SETTINGS":{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","Clients":[]}}`)}
	cfg, kinds, _, err := buildConfig(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbound) != 1 || cfg.Inbound[0].Tag != "b" {
		t.Fatalf("xray tag %q", cfg.Inbound[0].Tag)
	}
	msg, err := cfg.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*ss2022.MultiUserServerConfig); !ok {
		t.Fatalf("inbound runs %T, want the multi-user server", msg)
	}
	if kinds["b"].protocol != "shadowsocks" || kinds["b"].ssKeyLen != 16 {
		t.Fatalf("kind %+v", kinds["b"])
	}
}

// The certificate-path rewrite keeps big integers exactly and refuses
// objects whose keys differ only in case (re-encoding would change which
// one xray takes).
func TestRewriteCertPathsIsLossless(t *testing.T) {
	cert := `"certificates":[{"certificateFile":"` + nodeCertCredFile + `","keyFile":"` + nodeKeyCredFile + `"}]`
	files := certFiles{cert: "/s/c.pem", key: "/s/k.pem"}
	out, tags, err := rewriteCertPaths([]json.RawMessage{json.RawMessage(
		`{"tag":"t","big":9007199254740993,"streamSettings":{"tlsSettings":{` + cert + `}}}`)}, files)
	if err != nil || len(tags) != 1 {
		t.Fatalf("%v %v", tags, err)
	}
	if !strings.Contains(string(out[0]), "9007199254740993") || !strings.Contains(string(out[0]), "/s/c.pem") {
		t.Fatalf("rewrite lost precision or did not rewrite: %s", out[0])
	}
	for _, bad := range []string{
		`{"tag":"t","streamSettings":{"tlsSettings":{` + cert + `}},"StreamSettings":{}}`,
		`{"tag":"t","streamSettings":{"tlsSettings":{` + cert + `},"TLSSettings":{}}}`,
		`{"tag":"t","streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":"` + nodeCertCredFile +
			`","keyFile":"` + nodeKeyCredFile + `","KeyFile":"/x"}]}}}`,
		`{"tag":"t","streamSettings":{"tlsSettings":{` + cert + `,"Key":1,"key":2}}}`,
	} {
		if _, _, err := rewriteCertPaths([]json.RawMessage{json.RawMessage(bad)}, files); err == nil {
			t.Fatalf("case-colliding keys accepted: %s", bad)
		}
	}
}

func TestProcParsersRejectNonsense(t *testing.T) {
	for _, s := range []string{"NaN 1 1 1/2 3", "1 +Inf 1 1/2 3", "-1 1 1 1/2 3"} {
		if _, _, _, ok := parseLoadavg([]byte(s)); ok {
			t.Fatalf("%q accepted", s)
		}
	}
	m := parseMeminfo([]byte("MemTotal: 18446744073709551615 kB\nMemFree: 18446744073709551615 kB\nBuffers: 5 kB\nCached: 5 kB\n"))
	if m.total != ^uint64(0) || m.used != 0 {
		t.Fatalf("kB overflow wrapped: %+v", m)
	}
	if rss := parseStatusRSS([]byte("VmRSS: 18446744073709551615 kB\n")); rss != ^uint64(0) {
		t.Fatalf("VmRSS wrapped: %d", rss)
	}
}
