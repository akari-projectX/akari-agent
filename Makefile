.PHONY: bench build build-testkeys sign-tool sign-manifest check-release-keys dist proto sync-proto check-proto check-pb vet fmt-check test test-canary vulncheck ci

# Canonical contract lives in akari-panel/proto/agent.proto. This repo vendors
# a copy: `make sync-proto` pulls the sibling checkout's version and
# regenerates pb/; `make check-proto` fails when the vendored copy drifts.

# Version = nearest tag (or the short sha); injected together with the commit.
# Override for a release: make build VERSION=v0.2.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS  = -s -w -buildid= -X main.agentVersion=$(VERSION) -X main.gitSHA=$(COMMIT)
# Static, reproducible: no cgo, no VCS stamping, no build paths in the binary.
GOBUILD  = CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

build:
	$(GOBUILD) -o agent .

# TEST ONLY (smoke): an agent that also pins the public test release key
# (testdata/TEST-ONLY-release.key is committed, i.e. anyone can sign for
# it). Never ship this; `make dist` refuses binaries that contain it.
#   make build-testkeys VERSION=v900.0.0 OUT=/tmp/agent-v900
OUT ?= agent-testkeys
build-testkeys:
	CGO_ENABLED=0 go build -tags akari_testkeys -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(OUT) .

# Offline release-signing tool (cmd/akari-sign; see README "Release signing").
sign-tool:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o akari-sign ./cmd/akari-sign

# Signed self-update manifests for dist/ binaries:
#   make sign-manifest VERSION=v1.2.3 KEY=/secure/release.key   (or KEY_ENV=NAME)
# -> dist/akari-agent-linux-<arch>.manifest.json + .manifest.sig
MIN_PANEL_PROTOCOL ?= 3
sign-manifest:
	@test -n "$(KEY)$(KEY_ENV)" || { echo "KEY=<file> or KEY_ENV=<variable> required"; exit 1; }
	for a in $(DIST_ARCHS); do \
	  go run ./cmd/akari-sign sign $(if $(KEY),-key $(KEY),-key-env $(KEY_ENV)) \
	    -binary dist/akari-agent-linux-$$a -version $(VERSION) -min-panel-protocol $(MIN_PANEL_PROTOCOL) || exit 1; \
	done

# Release binaries must pin exactly release-keys.txt: never the test key.
TEST_PUBKEY = $(shell cut -d' ' -f1 testdata/TEST-ONLY-release.pub)
check-release-keys:
	@for f in dist/akari-agent-linux-*; do \
	  case "$$f" in *.manifest.*) continue ;; esac; \
	  if grep -qF "$(TEST_PUBKEY)" "$$f"; then echo "FAIL: $$f pins the TEST release key"; exit 1; fi; \
	done; echo "release keys: ok (no test key in dist/)"

# Release binaries (linux amd64 + arm64) and their checksums in dist/.
DIST_ARCHS ?= amd64 arm64
dist:
	rm -rf dist && mkdir dist
	for a in $(DIST_ARCHS); do \
	  GOOS=linux GOARCH=$$a $(GOBUILD) -o dist/akari-agent-linux-$$a . || exit 1; \
	done
	$(MAKE) check-release-keys
	cd dist && sha256sum akari-agent-linux-* > SHA256SUMS

proto:
	buf generate proto

sync-proto:
	cp ../akari-panel/proto/agent.proto proto/agent.proto
	$(MAKE) proto

check-proto:
	diff -q ../akari-panel/proto/agent.proto proto/agent.proto

# Generated code (pb/) must be what buf produces from the vendored proto.
# Needs protoc-gen-go v1.36.12 and protoc-gen-go-grpc v1.6.2 on PATH.
check-pb: proto
	git diff --exit-code -- pb

# govulncheck fails on any reachable vulnerability. VULN_ALLOW lists accepted
# IDs (each needs a reason here); anything else fails. Empty since R26
# (GO-2026-6443 fixed by pinning grpc-go to upstream 93e31b48545e; move to
# the v1.85.0 tag when it is released).
VULN_ALLOW ?=
vulncheck:
	@out=$$(go run golang.org/x/vuln/cmd/govulncheck@latest ./... 2>&1); rc=$$?; echo "$$out"; \
	[ $$rc -eq 0 ] && exit 0; \
	[ -z "$(strip $(VULN_ALLOW))" ] && { echo "reachable vulnerabilities (no allow-list)"; exit 1; }; \
	bad=$$(echo "$$out" | grep -oE '^Vulnerability #[0-9]+: GO-[0-9]+-[0-9]+' | grep -oE 'GO-[0-9]+-[0-9]+' | sort -u | grep -vxF "$$(echo $(VULN_ALLOW) | tr ' ' '\n')"); \
	if [ -n "$$bad" ]; then echo "NEW reachable vulnerabilities: $$bad"; exit 1; fi; \
	echo "only allow-listed vulnerabilities: $(VULN_ALLOW)"

# What CI runs (minus check-proto/check-pb, which need ../akari-panel).
ci: fmt-check vet test build vulncheck

vet:
	go vet ./...
	go vet -tags canary .

fmt-check:
	test -z "$$(gofmt -l .)"

test: test-canary
	go test -race ./...

# Per-protocol revocation canaries (rt_canary_test.go, build tag `canary`).
# No -race: xray's Vision client trips checkptr under the race detector.
# Bump xray-core only when these are green.
test-canary:
	go test -tags canary -count=1 -run 'TestRT_' .

# M2-6 overhead benchmarks at 10k users per node (bench_test.go; results in
# akari-panel/docs/PERF.md).
bench:
	go test -run '^$$' -bench . -benchmem ./...
