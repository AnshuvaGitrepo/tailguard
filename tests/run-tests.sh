#!/usr/bin/env bash
# Runs a tailguard tool against the fake tailscale fixtures and checks the
# JSON report against tests/expected.txt.
#
# Usage: tests/run-tests.sh sh [jq|python|awk]   test tailscale-audit.sh
#        tests/run-tests.sh exe TOOL FAKE_TS      test a Go build
# Needs python (python3 or python) to read the JSON reports.

# "cond && ok || bad" is safe here: ok() always succeeds.
# shellcheck disable=SC2015
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
MODE=${1:?usage: run-tests.sh sh [backend] | exe TOOL FAKE_TS}
PY=$(command -v python3 >/dev/null 2>&1 && python3 -c 1 >/dev/null 2>&1 && echo python3 || echo python)

# Windows-native exes need Windows paths and ';' as list separator.
winpath() { if command -v cygpath >/dev/null 2>&1 && [ "$MODE" != sh ]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

PASSED=0 FAILED=0
ok() { PASSED=$((PASSED + 1)); }
bad() { FAILED=$((FAILED + 1)); echo "  FAIL: $*"; }

# make_scanroot FIXTURE -> prints the folder the key scan should search.
# Fake auth keys are written here at test time instead of being stored in the
# repo, so code hosts' secret scanners never see a key-shaped string. The path
# is fixed (tests/.scan/FIXTURE) so both tools report the same file names.
make_scanroot() {
	local d="$HERE/.scan/$1" k="tskey"
	rm -rf "$d"
	mkdir -p "$d"
	[ -d "$HERE/fixtures/$1/scanroot" ] && cp -R "$HERE/fixtures/$1/scanroot/." "$d/"
	if [ "$1" = risky ]; then
		mkdir -p "$d/etc/systemd/system"
		printf '[Service]\nExecStartPost=/usr/bin/tailscale up --authkey=%s-auth-kTESTONLY11CNTRL-NotARealKeyXXXXXXXXXXXX\n' "$k" >"$d/etc/systemd/system/ts-join.service"
		printf 'echo hi\ntailscale up --auth-key %s-client-kTESTONLY22CNTRL-AlsoFakeYYYYYYYY\n' "$k" >"$d/.bash_history"
	fi
	printf '%s' "$d"
}
trap 'rm -rf "$HERE/.scan"' EXIT

run_tool() { # fixture policy outdir -> exit code
	local fx=$1 pol=$2 out=$3
	local args=(--no-color --out "$(winpath "$out")")
	[ -n "$pol" ] && args+=(--policy "$(winpath "$HERE/policies/$pol.hujson")")
	export FAKE_TS_DIR="$HERE/fixtures/$fx" FAKE_TS_LOG="$out/calls.log"
	export TAILGUARD_SCAN_ROOTS TAILGUARD_FWD_ROOT
	TAILGUARD_SCAN_ROOTS=$(winpath "$(make_scanroot "$fx")")
	# stands in for the running tailscaled (environ) and /etc; missing = daemon not found
	TAILGUARD_FWD_ROOT=$(winpath "$HERE/fixtures/$fx/fwd")
	if [ "$MODE" = sh ]; then
		TAILGUARD_TAILSCALE="$HERE/fake-tailscale/tailscale" TAILGUARD_JSON="${BACKEND:-}" \
			bash "$ROOT/tailscale-audit.sh" "${args[@]}" >"$out/console.txt" 2>&1
	else
		FAKE_TS_DIR=$(winpath "$FAKE_TS_DIR") FAKE_TS_LOG=$(winpath "$FAKE_TS_LOG") \
			TAILGUARD_TAILSCALE=$(winpath "$FAKE") "$TOOL" "${args[@]}" >"$out/console.txt" 2>&1
	fi
}

# check_case NAME FIXTURE POLICY WANT_EXIT
check_case() {
	local name=$1 fx=$2 pol=$3 want=$4 out rc
	out=$(mktemp -d)
	run_tool "$fx" "$pol" "$out"
	rc=$?
	echo "case $name (fixture=$fx policy=${pol:-none}) exit=$rc"
	[ "$rc" = "$want" ] && ok || bad "$name: exit $rc, want $want"

	local json
	json=$(find "$out" -maxdepth 1 -name 'tailscale-audit-*.json' | head -n1)
	if [ -z "$json" ]; then
		bad "$name: no JSON report written"; cat "$out/console.txt"; return
	fi
	ls "$out"/tailscale-audit-*.txt >/dev/null 2>&1 && ok || bad "$name: no TXT report"

	# read-only: only these five tailscale commands may run
	if [ -f "$out/calls.log" ]; then
		local badcalls
		badcalls=$(tr -d '\r' <"$out/calls.log" | grep -vxE 'version|status --json|debug prefs|serve status --json|lock status')
		[ -z "$badcalls" ] && ok || bad "$name: unexpected tailscale calls: $badcalls"
	fi

	# masked keys only
	if grep -q 'NotARealKey\|AlsoFake' "$out"/tailscale-audit-* "$out/console.txt"; then
		bad "$name: an auth key was printed unmasked"
	else ok; fi

	local got
	got=$("$PY" -c '
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
for f in r["findings"]:
    print("L", f["id"], f["status"])
for f in (r.get("policy") or {}).get("findings", []):
    print("P", f["id"], f["status"])
# every finding needs a plain title; every problem also needs an
# explanation and at least one fix step
for f in r["findings"] + (r.get("policy") or {}).get("findings", []):
    if not f.get("title"):
        print("BAD", f["id"], "no-title")
    if f["status"] in ("FAIL", "WARN", "UNKNOWN") and not (f.get("problem") and f.get("steps")):
        print("BAD", f["id"], "no-problem-or-steps")
' "$(winpath "$json")" | tr -d '\r') || { bad "$name: JSON report is not valid JSON"; return; }
	if grep -q '^BAD ' <<<"$got"; then
		bad "$name: incomplete explanations: $(grep '^BAD ' <<<"$got" | tr '\n' ';')"
	else ok; fi

	local key id st
	if [ -z "$pol" ]; then key=$fx; else key=policy-$pol; fi
	while read -r c id st; do
		[ "$c" = "$key" ] || continue
		if [ -z "$pol" ]; then
			grep -qx "L $id $st" <<<"$got" && ok || bad "$name: want $id=$st, got: $(grep " $id " <<<"$got" | head -n1)"
		else
			grep -qx "P $id $st" <<<"$got" && ok || bad "$name: missing policy finding $id=$st"
		fi
	done < <(grep -vE '^(#|$)' "$HERE/expected.txt")
	if [ -n "$pol" ]; then
		while read -r _ id st; do
			grep -qx "policy-$pol $id $st" "$HERE/expected.txt" && ok || bad "$name: unexpected policy finding $id=$st"
		done < <(grep '^P ' <<<"$got")
	fi
	rm -rf "$out"
}

# compare mode: both tools must print the same explanation for every case.
if [ "$MODE" = compare ]; then
	TOOL=${2:?compare needs TOOL path}
	FAKE=${3:?compare needs FAKE_TS path}
	# Fixed parser: auto-detect may call a python3 stub (Windows Store alias) that can hang.
	BACKEND="awk"
	echo "== same wording: tailscale-audit.sh vs $TOOL =="
	for c in risky: safe: unknown: server: safe:bad safe:mixed safe:good; do
		fx=${c%%:*} pol=${c#*:}
		out=$(mktemp -d)
		MODE="sh" run_tool "$fx" "$pol" "$out"
		mv "$out/console.txt" "$out/sh.txt"
		rm -f "$out"/tailscale-audit-*
		MODE=exe run_tool "$fx" "$pol" "$out"
		if "$PY" "$(winpath "$HERE/compare_output.py")" "$(winpath "$out/console.txt")" "$(winpath "$out/sh.txt")" >"$out/diff.txt"; then
			ok
			echo "case $fx${pol:+ + $pol policy}: same"
		else
			bad "$fx${pol:+ + $pol policy}: wording differs"
			head -30 "$out/diff.txt"
		fi
		rm -rf "$out"
	done
	echo "passed: $PASSED  failed: $FAILED"
	[ "$FAILED" -eq 0 ]
	exit
fi

case "$MODE" in
sh)
	BACKEND=${2:-}
	if [ "$BACKEND" = python ] && ! command -v python3 >/dev/null 2>&1; then
		echo "python3 not on PATH" >&2; exit 2
	fi
	echo "== tailscale-audit.sh, JSON backend: ${BACKEND:-auto} =="
	;;
exe)
	TOOL=${2:?exe needs TOOL path}
	FAKE=${3:?exe needs FAKE_TS path}
	echo "== $TOOL =="
	;;
*) echo "unknown mode $MODE" >&2; exit 2 ;;
esac

check_case risky risky "" 1
check_case safe safe "" 0
check_case unknown unknown "" 0
check_case server server "" 0
check_case policy-bad safe bad 1
check_case policy-mixed safe mixed 0
check_case policy-good safe good 0

# tool errors -> exit 2
out=$(mktemp -d)
if [ "$MODE" = sh ]; then
	bash "$ROOT/tailscale-audit.sh" --bogus >/dev/null 2>&1; rc1=$?
	printf '{ "ssh": [ {"src": ' >"$out/broken.hujson"
	FAKE_TS_DIR="$HERE/fixtures/safe" TAILGUARD_TAILSCALE="$HERE/fake-tailscale/tailscale" TAILGUARD_SCAN_ROOTS="$out" \
		bash "$ROOT/tailscale-audit.sh" --out "$out" --policy "$out/broken.hujson" >/dev/null 2>&1; rc2=$?
else
	"$TOOL" --bogus >/dev/null 2>&1; rc1=$?
	printf '{ "ssh": [ {"src": ' >"$out/broken.hujson"
	FAKE_TS_DIR=$(winpath "$HERE/fixtures/safe") TAILGUARD_TAILSCALE=$(winpath "$FAKE") TAILGUARD_SCAN_ROOTS=$(winpath "$out") \
		"$TOOL" --out "$(winpath "$out")" --policy "$(winpath "$out/broken.hujson")" >/dev/null 2>&1; rc2=$?
fi
echo "case errors: bad flag exit=$rc1, broken policy exit=$rc2"
[ "$rc1" = 2 ] && ok || bad "bad flag: exit $rc1, want 2"
[ "$rc2" = 2 ] && ok || bad "broken policy: exit $rc2, want 2"
rm -rf "$out"

# BusyBox's timeout kills grep with TERM (exit 143) instead of exiting 124.
# A scan cut short that way must give C10 UNKNOWN, never a false PASS.
if [ "$MODE" = sh ]; then
	out=$(mktemp -d)
	PATH="$HERE/fake-busybox-timeout:$PATH" run_tool safe "" "$out"
	json=$(find "$out" -maxdepth 1 -name 'tailscale-audit-*.json' | head -n1)
	c10=$("$PY" -c 'import json, sys
print(next(f["status"] for f in json.load(open(sys.argv[1], encoding="utf-8"))["findings"] if f["id"] == "C10"))' "$json" | tr -d '\r')
	echo "case busybox-timeout: C10=$c10"
	[ "$c10" = UNKNOWN ] && ok || bad "busybox-style timeout: C10=$c10, want UNKNOWN"
	rm -rf "$out"
fi

echo "passed: $PASSED  failed: $FAILED"
[ "$FAILED" -eq 0 ]
