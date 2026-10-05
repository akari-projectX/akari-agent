#!/usr/bin/env bash
# W37 tiered CI: which heavy job groups a change needs.
#
#   scripts/ci-changes.sh full              every group (push to main, nightly,
#                                           dispatch, release, `full-ci` label)
#   scripts/ci-changes.sh <base> <head>     groups touched by `git diff base head`
#
# Prints `<group>=true|false` lines (also appended to $GITHUB_OUTPUT in
# Actions). The ci/fuzz workflows run a group's job for real when it is true
# and skip it otherwise (a skipped job satisfies a required check). Changes
# to CI itself (.github/, this script) select every group: they validate
# themselves. Fail-safe: the jobs also run when this script fails.
set -euo pipefail

GROUPS_ALL="smoke systemd openrc reproducible fuzz"

# smoke: what the agent binary is made of (non-test Go code, modules, the
#   contract, the units it embeds) -> the panel's cross-repo smoke.
# systemd: the self-update hand-over (agent side, updater, units, release
#   verification, machine metrics read under the unit) and its test.
# openrc: the same hand-over on Alpine under OpenRC (W32): the updater, the
#   OpenRC scripts and what they run, and its test.
# reproducible: the build inputs that decide byte-identical output (toolchain
#   and modules, build flags). Source code alone cannot make the build
#   non-deterministic (no cgo, -trimpath, no VCS stamp); nightly and every
#   release check it regardless.
# fuzz: what the fuzz targets compile.
groups_of() {
  case "$1" in
    .github/* | scripts/ci-changes.sh) echo "$GROUPS_ALL" ;;
  esac
  case "$1" in
    *_test.go) ;;
    *.go | go.mod | go.sum | proto/* | pb/* | systemd/* | openrc/* | release-keys.txt | Makefile | \
      THIRD_PARTY_LICENSES.txt)
      echo smoke ;;
  esac
  case "$1" in
    update*.go | units*.go | manifest*.go | releasekeys*.go | release/* | \
      sysstat*.go | statfs*.go | boottime*.go | main.go | release-keys.txt | systemd/* | \
      scripts/systemd-test/* | go.mod | go.sum | Makefile)
      echo systemd ;;
  esac
  case "$1" in
    update*.go | units*.go | manifest*.go | releasekeys*.go | release/* | \
      sysstat*.go | statfs*.go | boottime*.go | main.go | release-keys.txt | openrc/* | \
      scripts/openrc-test/* | go.mod | go.sum | Makefile)
      echo openrc ;;
  esac
  case "$1" in
    go.mod | go.sum | Makefile)
      echo reproducible ;;
  esac
  case "$1" in
    *.go | go.mod | go.sum | testdata/fuzz/* | release/testdata/fuzz/*)
      echo fuzz ;;
  esac
}

if [ "${1:-}" = full ]; then
  selected="$GROUPS_ALL"
else
  [ $# -eq 2 ] || { echo "usage: $0 full | <base> <head>" >&2; exit 2; }
  files="$(git diff --name-only "$1" "$2")"
  selected=""
  while IFS= read -r f; do
    [ -n "$f" ] && selected="$selected $(groups_of "$f" | tr '\n' ' ')"
  done <<<"$files"
  echo "changed files: $(printf '%s\n' "$files" | grep -c . || true)" >&2
fi

for g in $GROUPS_ALL; do
  case " $selected " in
    *" $g "*) echo "$g=true" ;;
    *) echo "$g=false" ;;
  esac
done | tee -a "${GITHUB_OUTPUT:-/dev/null}"
