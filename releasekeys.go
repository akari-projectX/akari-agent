package main

import (
	_ "embed"
	"fmt"

	"akari/agent/release"
)

// The release keys this build trusts for self-update (release-keys.txt,
// compiled in). Production builds pin exactly that file.
//
//go:embed release-keys.txt
var releaseKeysText string

// testReleaseKeys is set only by builds with the `akari_testkeys` tag
// (releasekeys_testkeys.go: the PUBLIC test key whose private half is
// committed in testdata/). Such builds accept anything anyone signs with
// the test key and must never ship: `make dist` refuses to produce them.
var testReleaseKeys string

// pinnedReleaseKeys parses the compiled-in key set.
func pinnedReleaseKeys() ([]release.PublicKey, error) {
	keys, err := release.ParseKeys(releaseKeysText + "\n" + testReleaseKeys)
	if err != nil {
		return nil, fmt.Errorf("compiled-in release keys: %w", err)
	}
	return keys, nil
}
