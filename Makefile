.PHONY: build proto sync-proto check-proto vet fmt-check test test-canary

# Canonical contract lives in akari-panel/proto/agent.proto. This repo vendors
# a copy: `make sync-proto` pulls the sibling checkout's version and
# regenerates pb/; `make check-proto` fails when the vendored copy drifts.

build:
	go build -o agent -ldflags "-X main.agentVersion=v0.1.0" .

proto:
	buf generate proto

sync-proto:
	cp ../akari-panel/proto/agent.proto proto/agent.proto
	$(MAKE) proto

check-proto:
	diff -q ../akari-panel/proto/agent.proto proto/agent.proto

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
