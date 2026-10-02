#!/usr/bin/env bash
# W18/W23: the self-update path on a real node, without a panel. Debian 13
# with systemd 257 as PID 1, the units this repository ships (systemd/,
# compiled into the binary), and the agent's StateDirectory mounted
# noexec,idmapped as on a production VPS (the condition under which
# v0.4.0's exec-launcher failed with "permission denied"). Plays the
# agent's side of the hand-over (staged file + apply request, as update.go
# writes them) and checks what the privileged updater does:
#
#   1. a node installed with the pre-W23 units (scripts/systemd-test/
#      w18-units: ProcSubset=pid, updater without unit refresh): machine
#      metrics are reported unavailable and the units stale; an update
#      installs the binary but cannot refresh the units (read-only unit
#      directory in the old updater's sandbox: the one-time 重装命令);
#   2. the reinstall (units from the binary, -print-unit): every machine
#      metric is readable under the shipped unit, nothing stale;
#   3. a broken release with its own units: crash loop -> binary AND units
#      rolled back;
#   4. a good release with different units: installed with the binary
#      (root 0644, systemd reloaded), confirmed;
#   5. a hostile request (staged file a symlink to a root file): refused.
#
# The full flow with a panel (offer, download, rollout health gate,
# installer) is akari-panel's smoke (M6 section).
#
#   scripts/systemd-test/run.sh          (WORK=<dir>: scratch, default mktemp)
set -euo pipefail
cd "$(dirname "$0")/../.."
LEGACY=scripts/systemd-test/w18-units
W=${WORK:-$(mktemp -d)}
mkdir -p "$W"
C=akari-agent-systemd-test
cleanup() { docker rm -f "$C" >/dev/null 2>&1 || true; [ -n "${WORK:-}" ] || rm -rf "$W"; }
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  docker exec "$C" sh -c 'journalctl -u akari-agent-update -u akari-agent -o cat --no-pager | tail -40' || true
  exit 1
}

ARCH=$(go env GOARCH)
# vN: a release whose units differ from the canonical ones by a trailing
# comment (the binary carries them: go:embed of systemd/).
build_variant() { # version out
  rm -rf "$W/src" && mkdir -p "$W/src"
  tar --exclude=./.git -cf - . | tar -xf - -C "$W/src"
  for u in "$W"/src/systemd/*; do printf '# systemd-test build %s\n' "$1" >>"$u"; done
  make -s -C "$W/src" build-testkeys VERSION="$1" OUT="$2" >/dev/null
}
make -s build-testkeys VERSION=v900.0.0 OUT="$W/v0" >/dev/null
make -s build-testkeys VERSION=v900.0.1 OUT="$W/v1" >/dev/null
build_variant v900.0.3 "$W/v3"
CGO_ENABLED=0 go build -o "$W/akari-sign" ./cmd/akari-sign
# v2: broken (dies on every start) but carries units of its own.
"$W/v1" -print-units | python3 -c '
import json, sys
d = json.load(sys.stdin)
for n in d["units"]: d["units"][n] += "# systemd-test build v900.0.2 (broken)\n"
json.dump(d, open(sys.argv[1], "w"))' "$W/units2.json"
{ printf '#!/bin/sh\nif [ "$1" = -print-units ]; then cat <<'"'"'EOF'"'"'\n'
  cat "$W/units2.json"; printf '\nEOF\nexit 0\nfi\necho "broken agent build" >&2\nexit 3\n'; } >"$W/v2"
chmod 0755 "$W/v2"
cp "$W/v1" "$W/v4" # a valid, newer release for the hostile-request case
# v5: broken, with the canonical units v900.0.3 already has (case 6).
"$W/v3" -print-units >"$W/units5.json"
{ printf '#!/bin/sh\nif [ "$1" = -print-units ]; then cat <<'"'"'EOF'"'"'\n'
  cat "$W/units5.json"; printf '\nEOF\nexit 0\nfi\necho "broken agent build v5" >&2\nexit 3\n'; } >"$W/v5"
chmod 0755 "$W/v5"
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
  for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
    "$W/v$v" -print-unit "$u" >"$W/units$v.$u"
  done
done
python3 - "$W" <<'PY'
import json, sys
w = sys.argv[1]
for u, t in json.load(open(w + "/units2.json"))["units"].items():
    open("%s/units2.%s" % (w, u), "w").write(t)
PY
cmp -s "$W/units1.akari-agent.service" systemd/akari-agent.service || fail "v900.0.1 -print-unit is not systemd/akari-agent.service"
cmp -s "$W/units3.akari-agent.service" systemd/akari-agent.service && fail "v900.0.3 units do not differ"
# A bootstrap for a panel that is not there: the agent keeps retrying (it
# stays up), which is all the updater needs.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=test-ca -days 1 \
  -keyout /dev/null -out "$W/ca.pem" 2>/dev/null
{ printf 'panel_addr = "127.0.0.1:1"\nserver_name = "panel.invalid"\nenrollment_token = "unused"\n[identity]\nca_pem = """\n'
  cat "$W/ca.pem"; printf '"""\n'; } >"$W/bootstrap.toml"
mkdir -p "$W/legacy" && cp "$LEGACY"/* "$W/legacy/"
chmod -R a+rX "$W"

docker build -q -t akari-agent-systemd-test:debian13 scripts/systemd-test >/dev/null
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /var/lib/private:mode=0700 -v "$W:/w:ro" akari-agent-systemd-test:debian13 >/dev/null
x() { docker exec "$C" sh -c "$1"; }
for _ in $(seq 1 30); do x 'systemctl is-system-running 2>/dev/null' | grep -qE 'running|degraded' && break; sleep 1; done
U=/var/lib/private/akari-agent/update
SD=/etc/systemd/system
# The current invocation's journal of the agent.
alog() { x 'journalctl -o cat --no-pager _SYSTEMD_INVOCATION_ID=$(systemctl show -p InvocationID --value akari-agent)'; }
wait_alog() { # pattern
  for _ in $(seq 1 30); do alog | grep -q "$1" && return 0; sleep 0.5; done
  fail "agent log lacks '$1': $(alog | tail -5)"
}
# The "machine metrics" line of the current invocation, as JSON.
metrics_line() { wait_alog '"msg":"machine metrics'; alog | grep '"msg":"machine metrics' | tail -1; }
units_are() { # N: the installed units are release N's
  for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
    x "cmp -s /w/units$1.$u $SD/$u" || return 1
  done
}

echo "== 1. node installed with the pre-W23 units"
x "install -m 0755 /w/v0 /usr/local/bin/akari-agent
   install -d -m 0700 /etc/akari-agent && install -m 0600 /w/bootstrap.toml /etc/akari-agent/bootstrap.toml
   install -m 0644 /w/legacy/akari-agent.service /w/legacy/akari-agent-update.service /w/legacy/akari-agent-update.path $SD/
   systemctl daemon-reload && systemctl enable --now akari-agent.service akari-agent-update.path" >/dev/null 2>&1 \
  || fail "install"
for _ in $(seq 1 20); do x "test -d $U" && break; sleep 0.5; done
x "test -d $U" || fail "agent did not create its update dir"
# The production condition: the agent's state dir is noexec in its namespace.
x 'grep " /var/lib/private/akari-agent " /proc/$(systemctl show -p MainPID --value akari-agent)/mountinfo' | grep -q noexec \
  || fail "state dir not noexec (this container does not reproduce production)"
wait_alog '"updater":true'
# ProcSubset=pid hides the machine-wide /proc files: reported, not zeros.
metrics_line | python3 -c '
import json, sys
m = json.loads(sys.stdin.read())
assert m["level"] == "WARN", m
for k in ("cpu_percent", "memory", "load", "net", "sockets"): assert k in m["unavailable"], m
assert "process_rss" not in m["unavailable"] and "disk" not in m["unavailable"], m' \
  || fail "pre-W23 unit: metrics not reported unavailable: $(metrics_line)"
alog | grep '"msg":"the installed systemd units are not the ones' | grep -q '"akari-agent.service"' \
  || fail "stale units not reported"

stage() { # N: what the agent does (staged file, then the request: the trigger), as the agent's on-disk owner
  # The steps run seconds apart, so the agent has just been (re)started
  # several times: with the default start limit (5 starts in 10 s) the broken
  # build's restarts would hit "start request repeated too quickly" before
  # NRestarts reaches -update-max-boots. A production agent has run for a
  # while when an update arrives; start each case from a fresh counter.
  x "systemctl reset-failed akari-agent.service"
  x "own=\$(stat -c %u:%g $U)
     install -o \${own%:*} -g \${own#*:} -m 0600 /w/v$1 $U/staged
     install -o \${own%:*} -g \${own#*:} -m 0600 /w/req$1.json $U/.req && mv $U/.req $U/apply-request.json"
}
result() { x "cat $U/apply-result.json 2>/dev/null" || true; }
wait_result() { # state [secs]
  for _ in $(seq 1 "${2:-30}"); do result | grep -q "\"state\":\"$1\"" && return 0; sleep 1; done
  fail "no '$1' result (have: $(result))"
}
confirm() { # version: its self-check (needs a panel) is played here
  x "own=\$(stat -c %u:%g $U); printf $1 >$U/.c && chown \$own $U/.c && mv $U/.c $U/confirmed"
}
ulog() { x 'journalctl -u akari-agent-update -o cat --no-pager'; }

echo "== 1b. update v900.0.1 through the pre-W23 updater unit: binary yes, units no"
stage 1
wait_result installed
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "v900.0.1 not installed"
confirm v900.0.1
wait_result confirmed
ulog | grep -q 'systemd units NOT refreshed' || fail "no read-only unit dir warning"
for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
  x "cmp -s /w/legacy/$u $SD/$u" || fail "$u changed under the pre-W23 updater unit"
done

echo "== 2. the one-time reinstall: units from the binary"
x "for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
     /usr/local/bin/akari-agent -print-unit \$u >$SD/\$u; done
   systemctl daemon-reload && systemctl restart akari-agent.service" || fail "reinstall units"
units_are 1 || fail "reinstalled units are not v900.0.1's"
# Under the shipped unit every machine metric is readable.
metrics_line | python3 -c '
import json, sys
m = json.loads(sys.stdin.read())
assert m["level"] == "INFO" and m["unavailable"] == [], m
assert m["cpu_count"] > 0 and m["mem_total_bytes"] > 0 and m["net_interface"], m' \
  || fail "shipped unit: machine metrics not readable: $(metrics_line)"
alog | grep -q 'the installed systemd units are not the ones' && fail "current units reported stale"
x "/usr/local/bin/akari-agent -version" | grep -q 'v900.0.1 ' || fail "binary"

echo "== 3. broken v900.0.2 with its own units: crash loop -> binary and units rolled back"
x "rm -f $U/apply-result.json"
stage 2
# (The restarted v900.0.1 consumes the rolled_back result at once: its
# traces are the updater's record and the report the agent now owes.)
rolled() { x 'cat /var/lib/akari-agent-update/updater.json 2>/dev/null' | grep -q '"rolled_back":\["v900.0.2"\]'; }
for _ in $(seq 1 60); do rolled && break; sleep 1; done
rolled || fail "rolled-back version not recorded"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.1 ' || fail "not rolled back to v900.0.1"
ulog | grep -q 'stopped 3 times' || fail "rollback reason"
ulog | grep -q 'installed the new release.s systemd units' || fail "v900.0.2's units were not installed"
ulog | grep -q 'restored the previous systemd units' || fail "units not restored"
units_are 1 || fail "units after the rollback are not v900.0.1's"
x 'journalctl -u akari-agent -o cat --no-pager' | grep -q 'broken agent build' || fail "broken build never ran"
for _ in $(seq 1 20); do x "cat $U/state.json 2>/dev/null" | grep -q '"v900.0.2"' && break; sleep 0.5; done
x "cat $U/state.json" | grep -q '"state":5' || fail "agent owes no ROLLED_BACK report: $(x "cat $U/state.json")"
x 'systemctl is-active -q akari-agent' || fail "agent not running after the rollback"
[ "$(x 'systemctl show -p NeedDaemonReload --value akari-agent')" = no ] || fail "systemd not reloaded after the restore"

echo "== 4. v900.0.3 with different units: installed with the binary"
x "rm -f $U/apply-result.json"
stage 3
wait_result installed
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "v900.0.3 not installed"
units_are 3 || fail "v900.0.3's units not installed"
for u in akari-agent.service akari-agent-update.service akari-agent-update.path; do
  [ "$(x "stat -c '%a %u' $SD/$u")" = "644 0" ] || fail "$u mode/owner"
  x "cmp -s /w/units1.$u /var/lib/akari-agent-update/units.prev/$u" || fail "previous $u not kept"
done
[ "$(x 'systemctl show -p NeedDaemonReload --value akari-agent')" = no ] || fail "systemd not reloaded"
[ "$(x 'systemctl show -p NeedDaemonReload --value akari-agent-update.service')" = no ] || fail "systemd not reloaded (updater)"
wait_alog '"agent_version":"v900.0.3"'
alog | grep '"on_probation":true' | grep -q . || fail "new binary not on probation"
alog | grep -q 'the installed systemd units are not the ones' && fail "v900.0.3 reports its own units stale"
confirm v900.0.3
wait_result confirmed
[ -z "$(x 'find /var/lib/private/akari-agent -type f -perm /111')" ] || fail "executable file in the agent state dir"
[ "$(x "stat -c %u $U/apply-result.json")" = "$(x "stat -c %u $U")" ] || fail "result not handed to the agent"
x 'ls -a /etc/systemd/system' | grep -q 'akari-new' && fail "temporary unit files left"

echo "== 5. hostile request: a valid signed release, staged file a symlink to a root file"
x "own=\$(stat -c %u:%g $U); rm -f $U/staged $U/apply-result.json; ln -s /etc/shadow $U/staged
   install -o \${own%:*} -g \${own#*:} -m 0600 /w/req4.json $U/.req && mv $U/.req $U/apply-request.json"
wait_result rejected
result | grep -q 'symbolic links' || fail "rejected for another reason: $(result)"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "binary changed"
units_are 3 || fail "units changed"
x 'systemctl is-failed -q akari-agent-update.path' && fail "trigger unit failed"
echo "== 6. broken v900.0.5 trips systemd's start limit: fast rollback, healthy restored agent"
# Start limit 2 starts/60 s (a drop-in, as an operator would): the crash loop
# ends in "failed / start-limit-hit" with NRestarts frozen below
# -update-max-boots (3), the case the restart counter alone cannot see.
x "install -d $SD/akari-agent.service.d
   printf '[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=2\n[Service]\nRestartSec=1\n' >$SD/akari-agent.service.d/zz-limit.conf
   systemctl daemon-reload"
x "rm -f $U/apply-result.json"
t0=$SECONDS
stage 5
rolled5() { x 'cat /var/lib/akari-agent-update/updater.json 2>/dev/null' | grep -q '"rolled_back":\[[^]]*"v900.0.5"'; }
for _ in $(seq 1 100); do rolled5 && break; sleep 0.3; done
rolled5 || fail "v900.0.5 not rolled back"
dt=$((SECONDS - t0))
[ "$dt" -lt 30 ] || fail "rollback took ${dt}s (the self-check timeout is minutes: the start limit was not detected)"
ulog | grep -q 'start limit' || fail "rollback reason is not the start limit: $(ulog | tail -3)"
x 'journalctl -u akari-agent -o cat --no-pager' | grep -q 'start-limit-hit\|start request repeated too quickly' \
  || fail "the start limit never tripped (test does not exercise the case)"
x '/usr/local/bin/akari-agent -version' | grep -q 'akari-agent v900.0.3 ' || fail "not rolled back to v900.0.3"
for _ in $(seq 1 20); do [ "$(x 'systemctl is-active akari-agent')" = active ] && break; sleep 0.5; done
[ "$(x 'systemctl is-active akari-agent')" = active ] || fail "restored agent not running: $(x 'systemctl show -p ActiveState,Result akari-agent')"
sleep 4
[ "$(x 'systemctl is-active akari-agent')" = active ] || fail "restored agent did not stay up"
wait_alog '"agent_version":"v900.0.3"'
units_are 3 || fail "units changed"
echo "systemd self-update test: ok"
