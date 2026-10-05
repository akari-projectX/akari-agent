#!/usr/bin/env bash
# W32: the self-update path on an Alpine node, without a panel: Alpine 3.22
# with OpenRC as the init system, the OpenRC scripts this repository ships
# (openrc/, compiled into the binary), the agent under supervise-daemon as
# its own user with its state directory bind-mounted noexec. The OpenRC
# counterpart of scripts/systemd-test/run.sh: plays the agent's side of the
# hand-over (staged file + apply request, as update.go writes them) and
# checks what the privileged updater (openrc/akari-agent-update) does:
#
#   1. install (as the panel's installer does on Alpine: system user,
#      binary, bootstrap, scripts from -print-unit): the agent runs as
#      akari-agent with only CAP_NET_BIND_SERVICE and no_new_privs, its
#      state dir is noexec, credentials are in /run, every machine metric
#      is readable, nothing stale, the updater is detected;
#   2. a good release v900.0.1: installed, on probation, confirmed;
#   3. a broken release with its own scripts: respawn loop -> binary AND
#      scripts rolled back (supervise-daemon's respawn counter);
#   4. a good release with different scripts: installed with the binary
#      (root 0755), confirmed; the updater service itself is not restarted;
#   5. a hostile request (staged file a symlink to a root file): refused;
#   6. a broken release while conf.d sets respawn_max (supervise-daemon
#      gives up, the service ends stopped/failed): rolled back fast.
#
# The full flow with a panel (installer, offer, download, rollout) is
# akari-panel's smoke (Alpine section).
#
#   scripts/openrc-test/run.sh          (WORK=<dir>: scratch, default mktemp)
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${WORK:-$(mktemp -d)}
mkdir -p "$W"
C=akari-agent-openrc-test
cleanup() { [ -n "${KEEP:-}" ] || docker rm -f "$C" >/dev/null 2>&1 || true; [ -n "${WORK:-}" ] || rm -rf "$W"; }
trap cleanup EXIT
x() { docker exec "$C" sh -c "$1"; }
fail() {
  echo "FAIL: $*"
  x 'tail -40 /var/log/akari-agent/agent.log; echo "-- updater"; tail -40 /var/log/akari-agent-update.log
     echo "-- processes"; ps -o pid,ppid,user,args; echo "-- rc-status"; rc-status -a 2>&1 | grep -i akari
     echo "-- supervise-daemon state"; for f in /run/openrc/options/akari-agent/*; do echo "$f=$(cat "$f")"; done
     ls /run/openrc/failed /run/openrc/daemons/akari-agent 2>&1' || true
  exit 1
}

ARCH=$(go env GOARCH)
# vN: a release whose service files differ from the canonical ones by a
# trailing comment (the binary carries them: go:embed).
build_variant() { # version out
  rm -rf "$W/src" && mkdir -p "$W/src"
  tar --exclude=./.git -cf - . | tar -xf - -C "$W/src"
  for u in "$W"/src/systemd/* "$W"/src/openrc/*; do printf '# openrc-test build %s\n' "$1" >>"$u"; done
  make -s -C "$W/src" build-testkeys VERSION="$1" OUT="$2" >/dev/null
}
# broken VERSION UNITS_JSON OUT: dies on every start, prints the given units.
broken() {
  { printf '#!/bin/sh\nif [ "$1" = -print-units ]; then cat <<'"'"'EOF'"'"'\n'
    cat "$2"; printf '\nEOF\nexit 0\nfi\necho "broken agent build %s" >&2\nexit 3\n' "$1"; } >"$3"
  chmod 0755 "$3"
}
make -s build-testkeys VERSION=v900.0.0 OUT="$W/v0" >/dev/null
make -s build-testkeys VERSION=v900.0.1 OUT="$W/v1" >/dev/null
build_variant v900.0.3 "$W/v3"
CGO_ENABLED=0 go build -o "$W/akari-sign" ./cmd/akari-sign
"$W/v1" -print-units | python3 -c '
import json, sys
d = json.load(sys.stdin)
for n in d["units"]: d["units"][n] += "# openrc-test build v900.0.2 (broken)\n"
json.dump(d, open(sys.argv[1], "w"))' "$W/units2.json"
broken v900.0.2 "$W/units2.json" "$W/v2"
cp "$W/v1" "$W/v4" # a valid, newer release for the hostile-request case
"$W/v3" -print-units >"$W/units5.json"
broken v900.0.5 "$W/units5.json" "$W/v5"
for v in 1 2 3 4 5; do
  "$W/akari-sign" sign -key testdata/TEST-ONLY-release.key -binary "$W/v$v" -version "v900.0.$v" -os linux -arch "$ARCH" >/dev/null
  python3 - "$W/v$v" "v900.0.$v" >"$W/req$v.json" <<'PY'
import base64, json, sys
b = sys.argv[1]
print(json.dumps({"schema": 1, "kind": "apply", "rollout_id": "r" + sys.argv[2], "version": sys.argv[2],
                  "panel_protocol": 3, "manifest": base64.b64encode(open(b + ".manifest.json", "rb").read()).decode(),
                  "signatures": json.load(open(b + ".manifest.sig"))["signatures"]}))
PY
done
for v in 1 3; do
  for u in akari-agent akari-agent-update; do "$W/v$v" -print-unit "$u" >"$W/units$v.$u"; done
done
cmp -s "$W/units1.akari-agent" openrc/akari-agent || fail "v900.0.1 -print-unit is not openrc/akari-agent"
cmp -s "$W/units3.akari-agent" openrc/akari-agent && fail "v900.0.3 scripts do not differ"
# A bootstrap for a panel that is not there: the agent keeps retrying (it
# stays up), which is all the updater needs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=test-ca -days 1 \
  -keyout /dev/null -out "$W/ca.pem" 2>/dev/null
{ printf 'panel_addr = "127.0.0.1:1"\nserver_name = "panel.invalid"\nenrollment_token = "unused"\n[identity]\nca_pem = """\n'
  cat "$W/ca.pem"; printf '"""\n'; } >"$W/bootstrap.toml"
chmod -R a+rX "$W"

docker build -q -t akari-agent-openrc-test:alpine3.22 scripts/openrc-test >/dev/null
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --init --name "$C" --privileged -v "$W:/w:ro" akari-agent-openrc-test:alpine3.22 >/dev/null
for _ in $(seq 1 30); do x 'test -e /run/openrc/softlevel && rc-status >/dev/null 2>&1' && break; sleep 0.5; done
U=/var/lib/akari-agent/update
ID=/etc/init.d
LOGF=/var/log/akari-agent/agent.log
# The current run's log of the agent: from its last "self-update" line (the
# first thing every start logs).
alog() { x "awk '/\"msg\":\"self-update\"/ { n = NR } { l[NR] = \$0 } END { for (i = n; i <= NR; i++) if (n) print l[i] }' $LOGF"; }
wait_alog() { # pattern
  for _ in $(seq 1 30); do alog | grep -q "$1" && return 0; sleep 0.5; done
  fail "agent log lacks '$1': $(alog | tail -5)"
}
metrics_line() { wait_alog '"msg":"machine metrics'; alog | grep '"msg":"machine metrics' | tail -1; }
ulog() { x 'cat /var/log/akari-agent-update.log 2>/dev/null' || true; }
units_are() { # N: the installed scripts are release N's
  for u in akari-agent akari-agent-update; do x "cmp -s /w/units$1.$u $ID/$u" || return 1; done
}
# The agent process: supervise-daemon's child.
agent_pid() { x 'pgrep -P "$(cat /var/run/supervise-akari-agent.pid)" | head -1'; }

echo "== 1. install as the panel's installer does on Alpine"
x "addgroup -S akari-agent && adduser -S -D -H -h /var/lib/akari-agent -s /sbin/nologin -G akari-agent akari-agent
   install -m 0755 /w/v0 /usr/local/bin/akari-agent
   install -d -m 0700 /etc/akari-agent && install -m 0600 /w/bootstrap.toml /etc/akari-agent/bootstrap.toml
   for u in akari-agent akari-agent-update; do /usr/local/bin/akari-agent -print-unit \$u >$ID/\$u && chmod 0755 $ID/\$u; done
   rc-update add akari-agent default && rc-update add akari-agent-update default
   rc-service akari-agent start && rc-service akari-agent-update start" >/dev/null 2>&1 || fail "install"
for _ in $(seq 1 20); do x "test -d $U" && break; sleep 0.5; done
x "test -d $U" || fail "agent did not create its update dir"
wait_alog '"updater":true'
pid=$(agent_pid)
[ -n "$pid" ] && [ "$(x "stat -c %U /proc/$pid")" = akari-agent ] || fail "agent not running as akari-agent"
x "grep -E '^(CapEff|CapPrm|CapAmb):' /proc/$pid/status" | grep -qv '0000000000000400' && fail "agent capabilities: $(x "grep ^Cap /proc/$pid/status")"
x "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/$pid/status" || fail "agent without no_new_privs"
[ "$(x "awk '/Max open files/ { print \$4 }' /proc/$pid/limits")" = 1048576 ] || fail "LimitNOFILE"
# W^X: the state dir is noexec for everyone (bind mount), nothing there is executable.
x "awk '\$5 == \"/var/lib/akari-agent\" { print \$6 }' /proc/$pid/mountinfo" | grep -q noexec || fail "state dir not noexec"
x "cp /bin/busybox /var/lib/akari-agent/bb && chmod 0755 /var/lib/akari-agent/bb; /var/lib/akari-agent/bb true" 2>/dev/null \
  && fail "a file in the state dir was executed"
x "rm -f /var/lib/akari-agent/bb"
[ "$(x 'stat -c "%a %U" /var/lib/akari-agent /run/credentials/akari-agent.service /run/credentials/akari-agent.service/bootstrap.toml' | tr '\n' ' ')" \
  = "700 akari-agent 500 akari-agent 400 akari-agent " ] || fail "state/credential modes"
metrics_line | python3 -c '
import json, sys
m = json.loads(sys.stdin.read())
assert m["level"] == "INFO" and m["unavailable"] == [], m
assert m["cpu_count"] > 0 and m["mem_total_bytes"] > 0, m' || fail "machine metrics not readable: $(metrics_line)"
alog | grep -q 'units are not the ones' && fail "current scripts reported stale"
# A hand-edited script is reported stale (and the conf.d is the place for changes).
x "printf '# local edit\n' >>$ID/akari-agent && rc-service akari-agent restart" >/dev/null 2>&1
wait_alog '"msg":"machine metrics'
alog | grep '"msg":"the installed openrc units are not the ones' | grep -q '"akari-agent"' || fail "edited script not reported stale"
x "/usr/local/bin/akari-agent -print-unit akari-agent >$ID/akari-agent && rc-service akari-agent restart" >/dev/null 2>&1
wait_alog '"msg":"machine metrics'
alog | grep -q 'units are not the ones' && fail "restored script reported stale"
# Stop removes the credentials from /run.
x "rc-service akari-agent stop" >/dev/null 2>&1
x "test ! -e /run/credentials/akari-agent.service" || fail "credentials left after stop"
x "rc-service akari-agent start" >/dev/null 2>&1
wait_alog '"updater":true'

stage() { # N: what the agent does (staged file, then the request: the trigger), as the agent's on-disk owner
  x "install -o akari-agent -g akari-agent -m 0600 /w/v$1 $U/staged
     install -o akari-agent -g akari-agent -m 0600 /w/req$1.json $U/.req && mv $U/.req $U/apply-request.json"
}
result() { x "cat $U/apply-result.json 2>/dev/null" || true; }
wait_result() { # state [secs]
  for _ in $(seq 1 "${2:-30}"); do result | grep -q "\"state\":\"$1\"" && return 0; sleep 1; done
  fail "no '$1' result (have: $(result))"
}
confirm() { # version: its self-check (needs a panel) is played here
  x "printf $1 >$U/.c && chown akari-agent:akari-agent $U/.c && mv $U/.c $U/confirmed"
}
upd_sup() { x 'cat /var/run/supervise-akari-agent-update.pid'; }

echo "== 2. update to v900.0.1: installed, probation, confirmed"
sup0=$(upd_sup)
stage 1
wait_result installed
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "v900.0.1 not installed"
x '/usr/local/bin/akari-agent.prev -version' | grep -q 'akari-agent v900.0.0 ' || fail "previous binary not kept"
[ "$(x 'stat -c "%a %U" /usr/local/bin/akari-agent')" = "755 root" ] || fail "installed binary mode/owner"
wait_alog '"agent_version":"v900.0.1"'
alog | grep '"on_probation":true' | grep -q . || fail "new binary not on probation"
confirm v900.0.1
wait_result confirmed
units_are 1 || fail "scripts changed (identical in v900.0.1)"
ulog | grep -q 'agent update passed its self-check' || fail "updater did not see the confirmation"

echo "== 3. broken v900.0.2 with its own scripts: respawn loop -> binary and scripts rolled back"
x "rm -f $U/apply-result.json"
stage 2
rolled() { x 'cat /var/lib/akari-agent-update/updater.json 2>/dev/null' | grep -q "\"rolled_back\":\[[^]]*\"$1\""; }
for _ in $(seq 1 60); do rolled v900.0.2 && break; sleep 1; done
rolled v900.0.2 || fail "rolled-back version not recorded"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "not rolled back to v900.0.1"
ulog | grep -q 'stopped 3 times' || fail "rollback reason"
ulog | grep -q 'installed the new release.s openrc units' || fail "v900.0.2's scripts were not installed"
ulog | grep -q 'restored the previous openrc units' || fail "scripts not restored"
units_are 1 || fail "scripts after the rollback are not v900.0.1's"
x "grep -q 'broken agent build v900.0.2' $LOGF" || fail "broken build never ran"
for _ in $(seq 1 20); do x "cat $U/state.json 2>/dev/null" | grep -q '"v900.0.2"' && break; sleep 0.5; done
x "cat $U/state.json" | grep -q '"state":5' || fail "agent owes no ROLLED_BACK report: $(x "cat $U/state.json")"
x 'rc-service akari-agent status' >/dev/null 2>&1 || fail "agent not running after the rollback"
wait_alog '"agent_version":"v900.0.1"'

echo "== 4. v900.0.3 with different scripts: installed with the binary"
x "rm -f $U/apply-result.json"
stage 3
wait_result installed
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "v900.0.3 not installed"
units_are 3 || fail "v900.0.3's scripts not installed"
for u in akari-agent akari-agent-update; do
  [ "$(x "stat -c '%a %u' $ID/$u")" = "755 0" ] || fail "$u mode/owner"
  x "cmp -s /w/units1.$u /var/lib/akari-agent-update/units.prev/$u" || fail "previous $u not kept"
done
wait_alog '"agent_version":"v900.0.3"'
alog | grep '"on_probation":true' | grep -q . || fail "new binary not on probation"
alog | grep -q 'units are not the ones' && fail "v900.0.3 reports its own scripts stale"
confirm v900.0.3
wait_result confirmed
[ -z "$(x 'find /var/lib/akari-agent -type f -perm /111')" ] || fail "executable file in the agent state dir"
[ "$(x "stat -c %U $U/apply-result.json")" = akari-agent ] || fail "result not handed to the agent"
x "ls -a $ID" | grep -q 'akari-new' && fail "temporary script files left"
[ "$(upd_sup)" = "$sup0" ] || fail "the updater service was restarted along with the agent"

echo "== 5. hostile request: a valid signed release, staged file a symlink to a root file"
x "rm -f $U/staged $U/apply-result.json; ln -s /etc/shadow $U/staged; chown -h akari-agent:akari-agent $U/staged
   install -o akari-agent -g akari-agent -m 0600 /w/req4.json $U/.req && mv $U/.req $U/apply-request.json"
wait_result rejected
result | grep -q 'symbolic links' || fail "rejected for another reason: $(result)"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "binary changed"
units_are 3 || fail "scripts changed"
x 'rc-service akari-agent-update status' >/dev/null 2>&1 || fail "updater service not running"

echo "== 6. broken v900.0.5 while supervise-daemon gives up (conf.d respawn_max): fast rollback"
# respawn_max=1 (as an operator would set it in conf.d): the crash loop
# ends with the service stopped and marked failed, the respawn counter
# below -update-max-boots (3): the case the counter alone cannot see.
x "printf 'respawn_max=1\nrespawn_period=60\nrespawn_delay=1\n' >/etc/conf.d/akari-agent && rc-service akari-agent restart" >/dev/null 2>&1
wait_alog '"agent_version":"v900.0.3"'
x "rm -f $U/apply-result.json"
t0=$SECONDS
stage 5
for _ in $(seq 1 100); do rolled v900.0.5 && break; sleep 0.3; done
rolled v900.0.5 || fail "v900.0.5 not rolled back"
dt=$((SECONDS - t0))
[ "$dt" -lt 30 ] || fail "rollback took ${dt}s (the self-check timeout is minutes: the give-up was not detected)"
ulog | grep -q "openrc's start limit" || fail "rollback reason is not the give-up: $(ulog | tail -3)"
x "grep -q 'broken agent build v900.0.5' $LOGF" || fail "broken build never ran"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "not rolled back to v900.0.3"
for _ in $(seq 1 20); do x 'rc-service akari-agent status' >/dev/null 2>&1 && break; sleep 0.5; done
x 'rc-service akari-agent status' >/dev/null 2>&1 || fail "restored agent not running"
sleep 4
x 'rc-service akari-agent status' >/dev/null 2>&1 || fail "restored agent did not stay up"
wait_alog '"agent_version":"v900.0.3"'
units_are 3 || fail "scripts changed"
echo "openrc self-update test: ok"
