#!/bin/sh
# Statement coverage gate for the agent's revocation/billing core
# (ROADMAP §0). Usage: scripts/cover-gate.sh <coverprofile> [min%]
# Per file: covered statements / statements, from `go test -coverprofile`
# (duplicate blocks from several test binaries are merged: a block counts
# as covered if any run covered it). Fails if any file is below min.
set -eu
profile=$1
min=${2:-85}
files="gate.go ratelimit.go core.go"
fail=0
printf '%-14s %6s %8s %8s %5s\n' file stmts covered cover min
for f in $files; do
	line=$(awk -v f="/$f:" '
		NR > 1 && index($1, f) {
			split($0, a, " "); key = a[1]; n = a[2]; c = a[3]
			stmts[key] = n
			if (c > 0) hit[key] = 1
		}
		END {
			for (k in stmts) { t += stmts[k]; if (k in hit) h += stmts[k] }
			if (t == 0) { print "0 0 0.00"; exit }
			printf "%d %d %.2f\n", t, h, 100 * h / t
		}' "$profile")
	set -- $line
	ok=$(awk -v p="$3" -v m="$min" 'BEGIN { print (p + 0 >= m + 0) ? 1 : 0 }')
	mark=""
	if [ "$1" = 0 ] || [ "$ok" = 0 ]; then mark="  FAIL"; fail=1; fi
	printf '%-14s %6s %8s %7s%% %4s%%%s\n' "$f" "$1" "$2" "$3" "$min" "$mark"
done
exit $fail
