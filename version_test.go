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
