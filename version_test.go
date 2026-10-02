package main

import (
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	oldV, oldS := agentVersion, gitSHA
	t.Cleanup(func() { agentVersion, gitSHA = oldV, oldS })
	agentVersion, gitSHA = "v1.2.3", "abc123def456"
	got := versionString()
	for _, want := range []string{"akari-agent", "v1.2.3", "(abc123def456)", "/"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionString() = %q, missing %q", got, want)
		}
	}
}

// The embedded licence bundle is the generated file (R19): it states the
// binary's GPL-3.0-or-later status and carries the GPL and MIT texts.
func TestThirdPartyLicensesEmbedded(t *testing.T) {
	for _, want := range []string{
		"akari-agent: licences of the released binary",
		"GPL-3.0-or-later",
		"github.com/xtls/xray-core",
		"github.com/sagernet/sing ",
		"GNU GENERAL PUBLIC LICENSE",
		"Version 3, 29 June 2007",
		"MIT License",
	} {
		if !strings.Contains(thirdPartyLicenses, want) {
			t.Errorf("THIRD_PARTY_LICENSES.txt lacks %q", want)
		}
	}
}
