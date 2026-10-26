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
// binary's licensing (no GPL module is linked since xray-core v26.10.21) and
// carries the MIT text and the linked modules.
func TestThirdPartyLicensesEmbedded(t *testing.T) {
	for _, want := range []string{
		"akari-agent: licences of the released binary",
		"No GPL module is linked",
		"github.com/xtls/xray-core",
		"Mozilla Public License",
		"MIT License",
	} {
		if !strings.Contains(thirdPartyLicenses, want) {
			t.Errorf("THIRD_PARTY_LICENSES.txt lacks %q", want)
		}
	}
}
