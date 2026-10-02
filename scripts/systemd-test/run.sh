#!/usr/bin/env bash
# W18: the self-update path on a real node, without a panel. Debian 13 with
# systemd 257 as PID 1, the SHIPPED units (akari-panel/deploy/systemd), and
# the agent's StateDirectory mounted noexec,idmapped as on a production VPS
# (the condition under which v0.4.0's exec-launcher failed with
# "permission denied"). Plays the agent's side of the hand-over (staged file
# + apply request, as update.go writes them) and checks what the privileged
# updater does: install + confirm, crash-loop rollback, refusal of a
# hostile request. The full flow with a panel (offer, download, rollout
# health gate, installer) is akari-panel's smoke (M6 section).
#
#   scripts/systemd-test/run.sh [PANEL_DIR]     (default ../akari-panel)
set -euo pipefail
cd "$(dirname "$0")/../.."
PANEL_DIR=${1:-../akari-panel}
UNITS="$PANEL_DIR/deploy/systemd"
for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
  [ -f "$UNITS/$u" ] || { echo "FAIL: $UNITS/$u missing (akari-panel checkout with the W18 units?)"; exit 1; }
done
W=$(mktemp -d)
C=akari-agent-systemd-test
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; docker exec "$C" sh -c 'journalctl -u akari-agent-update -u akari-agent -o cat --no-pager | tail -40' || true; exit 1; }

ARCH=$(go env GOARCH)
make -s build-testkeys VERSION=v900.0.0 OUT="$W/v0" >/dev/null
make -s build-testkeys VERSION=v900.0.1 OUT="$W/v1" >/dev/null
CGO_ENABLED=0 go build -o "$W/akari-sign" ./cmd/akari-sign
printf '#!/bin/sh\necho "broken agent build" >&2\nexit 3\n' >"$W/v2"
chmod 0755 "$W/v2"
cp "$W/v1" "$W/v3" # a valid, newer release for the hostile-request case
for v in 1 2 3; do
  "$W/akari-sign" sign -key testdata/TEST-ONLY-release.key -binary "$W/v$v" -version "v900.0.$v" -os linux -arch "$ARCH" >/dev/null
  python3 - "$W/v$v" "v900.0.$v" >"$W/req$v.json" <<'PY'
import base64, json, sys
b = sys.argv[1]
print(json.dumps({"schema": 1, "kind": "apply", "rollout_id": "r" + sys.argv[2], "version": sys.argv[2],
                  "panel_protocol": 3, "manifest": base64.b64encode(open(b + ".manifest.json", "rb").read()).decode(),
                  "signatures": json.load(open(b + ".manifest.sig"))["signatures"]}))
PY
done
# A bootstrap for a panel that is not there: the agent keeps retrying (it
# stays up), which is all the updater needs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=test-ca -days 1 \
  -keyout /dev/null -out "$W/ca.pem" 2>/dev/null
{ printf 'panel_addr = "127.0.0.1:1"\nserver_name = "panel.invalid"\nenrollment_token = "unused"\n[identity]\nca_pem = """\n'
  cat "$W/ca.pem"; printf '"""\n'; } >"$W/bootstrap.toml"
cp "$UNITS"/akari-agent.service "$UNITS"/akari-agent-update.service "$UNITS"/akari-agent-update.path "$W/"

docker build -q -t akari-agent-systemd-test:debian13 scripts/systemd-test >/dev/null
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /var/lib/private:mode=0700 -v "$W:/w:ro" akari-agent-systemd-test:debian13 >/dev/null
x() { docker exec "$C" sh -c "$1"; }
for _ in $(seq 1 30); do x 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 1; done
x 'install -m 0755 /w/v0 /usr/local/bin/akari-agent
   install -d -m 0700 /etc/akari-agent && install -m 0600 /w/bootstrap.toml /etc/akari-agent/bootstrap.toml
   install -m 0644 /w/akari-agent.service /w/akari-agent-update.service /w/akari-agent-update.path /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now akari-agent.service akari-agent-update.path' >/dev/null 2>&1 \
  || fail "install"
for _ in $(seq 1 20); do x 'test -d /var/lib/private/akari-agent/update' && break; sleep 0.5; done
x 'test -d /var/lib/private/akari-agent/update' || fail "agent did not create its update dir"
# The production condition: the agent's state dir is noexec in its namespace.
x 'grep " /var/lib/private/akari-agent " /proc/$(systemctl show -p MainPID --value akari-agent)/mountinfo' | grep -q noexec \
  || fail "state dir not noexec (this container does not reproduce production)"
x 'journalctl -u akari-agent -o cat --no-pager' | grep -q '"updater":true' || fail "agent does not see the updater unit"

U=/var/lib/private/akari-agent/update
# stage N: what the agent does (staged file, then the request: the trigger),
# as the agent's on-disk owner.
stage() {
  x "own=\$(stat -c %u:%g $U)
     install -o \${own%:*} -g \${own#*:} -m 0600 /w/v$1 $U/staged
     install -o \${own%:*} -g \${own#*:} -m 0600 /w/req$1.json $U/.req && mv $U/.req $U/apply-request.json"
}
result() { x "cat $U/apply-result.json 2>/dev/null" || true; }
wait_result() { # $1 = state
  for _ in $(seq 1 "${2:-30}"); do result | grep -q "\"state\":\"$1\"" && return 0; sleep 1; done
  fail "no '$1' result (have: $(result))"
}

echo "== install v900.0.1 and confirm"
stage 1
wait_result installed
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "v900.0.1 not installed"
x '/usr/local/bin/akari-agent.prev -version' | grep -q 'akari-agent v900.0.0 ' || fail "previous binary not kept"
[ "$(x 'stat -c "%a %u" /usr/local/bin/akari-agent')" = "755 0" ] || fail "installed binary mode/owner"
for _ in $(seq 1 20); do x 'journalctl -u akari-agent -o cat --no-pager' | grep -q '"agent_version":"v900.0.1"' && break; sleep 0.5; done
x 'journalctl -u akari-agent -o cat --no-pager' | grep '"on_probation":true' | grep -q . || fail "new binary not on probation"
# Its self-check (needs a panel) is played here: the confirmation marker.
x "own=\$(stat -c %u:%g $U); printf v900.0.1 >$U/.c && chown \$own $U/.c && mv $U/.c $U/confirmed"
wait_result confirmed
[ "$(result | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')" = confirmed ] || fail "result"
[ -z "$(x 'find /var/lib/private/akari-agent -type f -perm /111')" ] || fail "executable file in the agent state dir"
[ "$(x "stat -c %u $U/apply-result.json")" = "$(x "stat -c %u $U")" ] || fail "result not handed to the agent"

echo "== broken v900.0.2: crash loop -> rollback"
stage 2
# (The restarted v900.0.1 consumes the rolled_back result at once: its
# traces are the updater's record and the report the agent now owes.)
rolled() { x 'cat /var/lib/akari-agent-update/updater.json 2>/dev/null' | grep -q '"rolled_back":\["v900.0.2"\]'; }
for _ in $(seq 1 60); do rolled && break; sleep 1; done
rolled || fail "rolled-back version not recorded"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "not rolled back to v900.0.1"
x 'journalctl -u akari-agent-update -o cat --no-pager' | grep -q 'stopped 3 times' || fail "rollback reason"
x 'journalctl -u akari-agent -o cat --no-pager' | grep -q 'broken agent build' || fail "broken build never ran"
for _ in $(seq 1 20); do x "cat $U/state.json 2>/dev/null" | grep -q '"v900.0.2"' && break; sleep 0.5; done
x "cat $U/state.json" | grep -q '"state":5' || fail "agent owes no ROLLED_BACK report: $(x "cat $U/state.json")"
x 'systemctl is-active -q akari-agent' || fail "agent not running after the rollback"

echo "== hostile request: a valid signed release, staged file a symlink to a root file"
x "own=\$(stat -c %u:%g $U); rm -f $U/staged $U/apply-result.json; ln -s /etc/shadow $U/staged
   install -o \${own%:*} -g \${own#*:} -m 0600 /w/req3.json $U/.req && mv $U/.req $U/apply-request.json"
wait_result rejected
result | grep -q 'symbolic links' || fail "rejected for another reason: $(result)"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "binary changed"
x 'systemctl is-failed -q akari-agent-update.path' && fail "trigger unit failed"
echo "systemd self-update test: ok"
