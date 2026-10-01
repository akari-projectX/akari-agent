//go:build akari_testkeys

package main

// TEST ONLY: the smoke test's release key (private half in
// testdata/TEST-ONLY-release.key, public). Never in a release build.
func init() {
	testReleaseKeys = "vRaBp2ipakKPUi8YJg00NXCsSqhxLSMgE5UusAbaCuM= TEST-ONLY-DO-NOT-SHIP"
}
