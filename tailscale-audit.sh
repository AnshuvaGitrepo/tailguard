#!/usr/bin/env bash
# tailscale-audit.sh - read-only Tailscale security audit (Tailworm, Oct 2026).
#
# Runs on any Linux distro with bash. Uses jq or python3 for JSON when present,
# and falls back to a built-in awk parser otherwise. Never changes any setting.
#
# Usage: tailscale-audit.sh [--policy FILE] [--no-color] [--out DIR] [--help]
# Exit:  0 = no FAIL, 1 = at least one FAIL, 2 = the tool itself errored.
#
# Test hooks (env): TAILGUARD_TAILSCALE=path to tailscale binary,
#   TAILGUARD_JSON=jq|python|awk to force a JSON backend,
#   TAILGUARD_SCAN_ROOTS=dir1:dir2 to replace the auth-key search paths.

set -u

TOOL_VERSION="1.1.1"
MIN_SAFE_VERSION="1.98.9"

POLICY_FILE=""
OUT_DIR=""
USE_COLOR=1
USE_PROGRESS=1

usage() {
	cat <<'EOF'
tailscale-audit.sh - read-only Tailscale security audit

Usage: tailscale-audit.sh [options]

Options:
  --policy FILE   Also audit an exported tailnet policy file (HuJSON)
  --no-color      Plain console output
  --out DIR       Where to write the .txt and .json reports
                  (default: the folder this script is in)
  --no-progress   Do not show the progress bar while scanning
  --help          Show this help

Exit codes: 0 no FAIL, 1 at least one FAIL, 2 tool error.
This tool only reads. It never changes any Tailscale setting.
EOF
}

die() {
	progress_done
	printf 'tailscale-audit: error: %s\n' "$1" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--policy)
		[ $# -ge 2 ] || die "--policy needs a file"
		POLICY_FILE="$2"
		shift 2
		;;
	--policy=*)
		POLICY_FILE="${1#--policy=}"
		shift
		;;
	--out)
		[ $# -ge 2 ] || die "--out needs a directory"
		OUT_DIR="$2"
		shift 2
		;;
	--out=*)
		OUT_DIR="${1#--out=}"
		shift
		;;
	--no-color)
		USE_COLOR=0
		shift
		;;
	--no-progress)
		USE_PROGRESS=0
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "unknown option: $1"
		;;
	esac
done

if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
	USE_COLOR=0
fi
if [ "$USE_COLOR" -eq 1 ]; then
	# bright colours read well on both black and PowerShell-blue backgrounds
	C_PASS=$'\033[92m' C_WARN=$'\033[93m' C_FAIL=$'\033[91m'
	C_INFO=$'\033[96m' C_UNK=$'\033[95m' C_BOLD=$'\033[1m' C_OFF=$'\033[0m'
else
	C_PASS="" C_WARN="" C_FAIL="" C_INFO="" C_UNK="" C_BOLD="" C_OFF=""
fi

# ---------------------------------------------------------------- progress
# One-line step bar on stderr, only when stderr is a terminal. It is erased
# before the results print and never goes into the report files.
[ -t 2 ] || USE_PROGRESS=0
PROG_STEP=0
PROG_TOTAL=6
[ -n "$POLICY_FILE" ] && PROG_TOTAL=7
PROG_WIDTH=0

progress() { # progress LABEL [DETAIL] -> next step; progress_detail updates in place
	[ "$USE_PROGRESS" -eq 1 ] || return 0
	PROG_STEP=$((PROG_STEP + 1))
	PROG_LABEL=$1
	progress_draw "${2:-}"
}

progress_detail() {
	[ "$USE_PROGRESS" -eq 1 ] || return 0
	progress_draw "$1"
}

progress_draw() {
	local filled=$((16 * PROG_STEP / PROG_TOTAL)) bar line cols
	bar=$(printf '%*s' "$filled" '' | tr ' ' '#')$(printf '%*s' $((16 - filled)) '' | tr ' ' '-')
	line=$(printf '[%s] %d/%d %s  %d:%02d' "$bar" "$PROG_STEP" "$PROG_TOTAL" "$PROG_LABEL" $((SECONDS / 60)) $((SECONDS % 60)))
	[ -n "$1" ] && line="$line  | $1"
	cols=${COLUMNS:-80}
	[ "${#line}" -ge "$cols" ] && line="${line:0:$((cols - 4))}..."
	printf '\r%-*s' "$PROG_WIDTH" "$line" >&2
	[ "${#line}" -gt "$PROG_WIDTH" ] && PROG_WIDTH=${#line}
	return 0
}

progress_done() {
	[ "${USE_PROGRESS:-0}" -eq 1 ] && [ "${PROG_WIDTH:-0}" -gt 0 ] && printf '\r%*s\r' "$PROG_WIDTH" '' >&2
	return 0
}

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t tailguard) || die "cannot create temp dir"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- JSON helpers
# Every backend flattens JSON to lines of "PATH<TAB>VALUE", for example
# ".Self.HostName	web-01" or ".ssh[0].src[1]	tag:prod". Empty containers
# print as [] or {}. Checks only use this format, so all backends match.
# The awk and jq programs below are meant to be single-quoted.
# shellcheck disable=SC2016

AWK_FLATTEN='
function skipws(   c) {
	while (pos <= n) {
		c = substr(s, pos, 1)
		if (c == " " || c == "\t" || c == "\n" || c == "\r") pos++
		else break
	}
}
function pstr(   out, c, e) {
	pos++
	out = ""
	while (pos <= n) {
		c = substr(s, pos, 1)
		if (c == "\\") {
			e = substr(s, pos + 1, 1)
			if (e == "n" || e == "t" || e == "r") out = out " "
			else if (e == "u") out = out "\\u"
			else out = out e
			pos += 2
			continue
		}
		if (c == "\"") { pos++; return out }
		out = out c
		pos++
	}
	err = 1
	return out
}
function pval(path,   c, k, i, v, start) {
	skipws()
	c = substr(s, pos, 1)
	if (c == "{") {
		pos++; skipws()
		if (substr(s, pos, 1) == "}") { pos++; print path "\t{}"; return }
		while (1) {
			skipws()
			if (substr(s, pos, 1) != "\"") { err = 1; return }
			k = pstr(); skipws()
			if (substr(s, pos, 1) != ":") { err = 1; return }
			pos++
			pval(path "." k)
			if (err) return
			skipws()
			c = substr(s, pos, 1); pos++
			if (c == ",") continue
			if (c == "}") return
			err = 1; return
		}
	}
	if (c == "[") {
		pos++; skipws()
		if (substr(s, pos, 1) == "]") { pos++; print path "\t[]"; return }
		i = 0
		while (1) {
			pval(path "[" i "]")
			if (err) return
			i++; skipws()
			c = substr(s, pos, 1); pos++
			if (c == ",") continue
			if (c == "]") return
			err = 1; return
		}
	}
	if (c == "\"") { v = pstr(); print path "\t" v; return }
	start = pos
	while (pos <= n && substr(s, pos, 1) !~ /[],} \t\r\n]/) pos++
	v = substr(s, start, pos - start)
	if (v == "") { err = 1; return }
	print path "\t" v
}
{ buf = buf $0 "\n" }
END {
	s = buf; n = length(s); pos = 1; err = 0
	pval("")
	if (err) exit 3
	skipws()
	if (pos <= n) exit 3
}'

# HuJSON -> JSON: drop // and /* */ comments outside strings and trailing commas.
# shellcheck disable=SC2016
AWK_HUJSON='
{ buf = buf $0 "\n" }
END {
	s = buf; n = length(s); out = ""; i = 1; ins = 0
	while (i <= n) {
		c = substr(s, i, 1)
		if (ins) {
			out = out c
			if (c == "\\") { out = out substr(s, i + 1, 1); i += 2; continue }
			if (c == "\"") ins = 0
			i++; continue
		}
		if (c == "\"") { ins = 1; out = out c; i++; continue }
		if (c == "/" && substr(s, i + 1, 1) == "/") {
			while (i <= n && substr(s, i, 1) != "\n") i++
			continue
		}
		if (c == "/" && substr(s, i + 1, 1) == "*") {
			i += 2
			while (i <= n && !(substr(s, i, 1) == "*" && substr(s, i + 1, 1) == "/")) i++
			i += 2; continue
		}
		if (c == "}" || c == "]") {
			j = length(out)
			while (j > 0 && substr(out, j, 1) ~ /[ \t\r\n]/) j--
			if (j > 0 && substr(out, j, 1) == ",") out = substr(out, 1, j - 1) substr(out, j + 1)
		}
		out = out c; i++
	}
	printf "%s", out
}'

PY_FLATTEN='
import json, sys
def clean(v):
    return v.replace("\t", " ").replace("\n", " ").replace("\r", " ")
def walk(p, v):
    if isinstance(v, dict):
        if not v:
            print(p + "\t{}")
        for k, x in v.items():
            walk(p + "." + clean(k), x)
    elif isinstance(v, list):
        if not v:
            print(p + "\t[]")
        for i, x in enumerate(v):
            walk(p + "[" + str(i) + "]", x)
    elif isinstance(v, str):
        print(p + "\t" + clean(v))
    else:
        print(p + "\t" + json.dumps(v))
try:
    data = json.load(open(sys.argv[1], encoding="utf-8-sig"))
except Exception:
    sys.exit(3)
walk("", data)'

# shellcheck disable=SC2016
JQ_FLATTEN='paths as $p | getpath($p) as $v
| select((($v|type) != "array" and ($v|type) != "object") or ($v|length) == 0)
| ($p | map(if type == "number" then "[" + tostring + "]" else "." + . end) | join(""))
  + "\t"
  + ($v | if type == "string" then gsub("[\t\n\r]"; " ")
          elif type == "array" then "[]" elif type == "object" then "{}"
          else tojson end)'

pick_json_backend() {
	case "${TAILGUARD_JSON:-}" in
	jq | python | awk)
		JSON_BACKEND="$TAILGUARD_JSON"
		return
		;;
	esac
	if command -v jq >/dev/null 2>&1; then
		JSON_BACKEND=jq
	elif command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1; then
		JSON_BACKEND=python
	else
		JSON_BACKEND="awk"
	fi
}

# json_flat IN OUT -> 0 on success, non-zero if IN is not valid JSON.
json_flat() {
	case "$JSON_BACKEND" in
	jq) jq -r "$JQ_FLATTEN" "$1" >"$2" 2>/dev/null ;;
	python) python3 -c "$PY_FLATTEN" "$1" >"$2" 2>/dev/null ;;
	*) tr -d '\r' <"$1" | awk "$AWK_FLATTEN" >"$2" 2>/dev/null ;;
	esac
}

# jget FLAT PATH -> prints value, returns 1 if the path is missing.
jget() {
	awk -F'\t' -v p="$2" '$1 == p { print substr($0, length($1) + 2); f = 1; exit } END { exit !f }' "$1"
}

# jlist FLAT PREFIX -> prints the values of PREFIX[0], PREFIX[1], ... (scalars only).
jlist() {
	awk -F'\t' -v p="$2" 'index($1, p "[") == 1 && substr($1, length(p) + 2) ~ /^[0-9]+\]$/ { print substr($0, length($1) + 2) }' "$1"
}

# jhas FLAT PREFIX -> true if any path starts with PREFIX.
jhas() {
	awk -F'\t' -v p="$2" 'index($1, p) == 1 { f = 1; exit } END { exit !f }' "$1"
}

# jindexes FLAT PREFIX -> distinct array indexes under PREFIX (e.g. ".ssh").
jindexes() {
	awk -F'\t' -v p="$2" 'index($1, p "[") == 1 { r = substr($1, length(p) + 2); sub(/\].*/, "", r); if (r ~ /^[0-9]+$/ && !(r in seen)) { seen[r] = 1; print r } }' "$1"
}

json_esc() {
	local s=$1
	s=${s//\\/\\\\}
	s=${s//\"/\\\"}
	s=${s//$'\t'/\\t}
	s=${s//$'\n'/\\n}
	s=${s//$'\r'/\\r}
	printf '%s' "$s"
}

# ---------------------------------------------------------------- findings
# One entry per finding. KIND is L (this device) or P (policy file).
# CHECK, DETAIL and FIX are the short technical form; TITLE, PROBLEM, WHY,
# STEPS, HELP and NEXT are the plain-English explanation shown to people.
# The wording matches the Go tool (go/checks.go, go/policy_audit.go).
F_KIND=() F_ID=() F_STATUS=() F_CHECK=() F_TITLE=() F_DETAIL=() F_FIX=()
F_PROBLEM=() F_WHY=() F_HELP=() F_NEXT=() F_STEPS=() F_GROUP=() F_REF=()
RULE_SUMMARY=() RULE_JSON=()
US=$'\x1f' # separates the steps inside one F_STEPS entry
GROUP="" REF=""

# add KIND ID STATUS CHECK TITLE DETAIL PROBLEM WHY HELP NEXT [STEP...]
# Findings with the same $GROUP are shown as one card listing every $REF.
add() {
	local kind=$1 id=$2 st=$3 check=$4 title=$5 detail=$6 problem=$7 why=$8 help=$9 next=${10}
	shift 10
	local steps="" fix="-" i=1 s
	for s in "$@"; do
		steps="${steps:+$steps$US}$s"
		if [ "$i" -eq 1 ]; then fix="1) $s"; else fix="$fix $i) $s"; fi
		i=$((i + 1))
	done
	F_KIND+=("$kind") F_ID+=("$id") F_STATUS+=("$st") F_CHECK+=("$check") F_TITLE+=("$title")
	F_DETAIL+=("$detail") F_FIX+=("$fix") F_PROBLEM+=("$problem") F_WHY+=("$why") F_HELP+=("$help")
	F_NEXT+=("$next") F_STEPS+=("$steps") F_GROUP+=("$GROUP") F_REF+=("$REF")
}

pass() { add L "$1" PASS "$2" "$3" "$4" "" "" "" ""; }               # ID CHECK TITLE DETAIL
info() { add L "$1" INFO "$2" "$3" "$4" "${5:-}" "" "" ""; }         # ID CHECK TITLE DETAIL [NOTE]
unknown() { # ID CHECK TITLE DETAIL PROBLEM STEP...
	local id=$1 check=$2 title=$3 detail=$4 problem=$5
	shift 5
	add L "$id" UNKNOWN "$check" "$title" "$detail" "$problem" "" "" "" "$@"
}
prefs_unknown() { # ID CHECK TITLE FIELD
	unknown "$1" "$2" "$3" "'tailscale debug prefs' failed or has no $4" \
		"This version of Tailscale did not report this setting, so the tool can't tell." \
		"Run this by hand and look for $4: tailscale debug prefs"
}

# ver_lt A B -> true if version A < B (numeric x.y.z).
ver_lt() {
	local IFS=.
	local -a a b
	read -r -a a <<<"$1"
	read -r -a b <<<"$2"
	local i x y
	for i in 0 1 2; do
		x=${a[$i]:-0} y=${b[$i]:-0}
		x=${x%%[!0-9]*} y=${y%%[!0-9]*}
		x=${x:-0} y=${y:-0}
		if ((10#$x < 10#$y)); then return 0; fi
		if ((10#$x > 10#$y)); then return 1; fi
	done
	return 1
}

mask_key() {
	printf '%s****(masked)' "${1:0:10}"
}

FWD_VAR="TS_SSH_DISABLE_FORWARDING"

# fwd_truthy VALUE -> true for the values tailscaled's envknob accepts as true.
fwd_truthy() {
	local v=$1
	v=${v//[\"\' $'\r']/}
	case "$v" in 1 | t | T | TRUE | true | True) return 0 ;; esac
	return 1
}

# fwd_from_env FILE -> true if NUL- or newline-separated KEY=VALUE text turns the switch on.
fwd_from_env() {
	fwd_truthy "$(tr '\0' '\n' <"$1" | awk -v k="$FWD_VAR" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }')"
}

# fwd_from_conf FILE -> true if a config file turns the switch on. Matches
# TS_SSH_DISABLE_FORWARDING=1 (/etc/default) and Environment="...=1" (systemd); last wins.
fwd_from_conf() {
	fwd_truthy "$(tr -d '\r' <"$1" | awk -v k="$FWD_VAR=" '{
		l = $0; sub(/^[ \t]+/, "", l)
		if (substr(l, 1, 1) == "#") next
		i = index(l, k); if (!i) next
		v = substr(l, i + length(k))
		if (match(v, /[ \t"]/)) v = substr(v, 1, RSTART - 1)
		last = v
	} END { print last }')"
}

# ---------------------------------------------------------------- local checks
pick_json_backend

IS_ROOT=0
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1
SKIPPED=()
SUDO="sudo "
AGAIN="Run this check again."

TS="${TAILGUARD_TAILSCALE:-}"
if [ -z "$TS" ]; then
	TS=$(command -v tailscale 2>/dev/null || true)
fi
if [ -n "$TS" ] && [ ! -x "$TS" ]; then
	TS=""
fi

run_ts() { # run_ts OUTFILE args... -> exit code of tailscale
	local out=$1
	shift
	"$TS" "$@" >"$out" 2>"$out.err"
}
ts_err() { head -c 200 "$1.err" | tr '\n' ' '; }

STATUS_OK=0 PREFS_OK=0 SELF_OK=0 BACKEND=""
if [ -z "$TS" ]; then
	PROG_STEP=4
	progress "tailscale CLI not found, skipping"
	info C01 "Tailscale installed" "Tailscale was not found on this device, so only the file search ran" "tailscale CLI not found on PATH"
	for c in "C02:Daemon running and logged in" "C03:Tailscale SSH server" "C04:Control server" \
		"C05:Tailnet Lock" "C06:Node key expiry" "C07:Auto-updates" "C08:Serve Unix-socket targets" \
		"C09:App connector" "C11:Peers with Tailscale SSH" "C13:SSH forwarding off-switch"; do
		unknown "${c%%:*}" "${c#*:}" "Skipped: ${c#*:} (Tailscale not found)" "skipped: tailscale CLI not found" \
			"The tailscale command could not be found." "Install Tailscale, or put the tailscale command on PATH, then run this check again."
	done
else
	# 1. version
	progress "Checking Tailscale version"
	C1="Tailscale version"
	VSTEP="Run it by hand and check the version is $MIN_SAFE_VERSION or newer: tailscale version"
	if run_ts "$TMP/version" version; then
		FIRST=$(head -n1 "$TMP/version" | tr -d '\r')
		VER=$(printf '%s' "$FIRST" | awk '{print $1}')
		VER=${VER%%-*}
		if ! printf '%s' "$VER" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
			unknown C01 "$C1" "Could not read the Tailscale version" "could not parse version from: $FIRST" \
				"The tool did not understand the version text: $FIRST" "$VSTEP"
		elif ver_lt "$VER" "$MIN_SAFE_VERSION"; then
			add L C01 FAIL "$C1" "Tailscale is out of date (version $VER)" \
				"version $VER < $MIN_SAFE_VERSION (TS-2026-009 and other SSH fixes)" \
				"This version is older than $MIN_SAFE_VERSION and has known Tailscale SSH security bugs that are already fixed in newer versions." \
				"These bugs are public, so attackers know how to use them against old versions." \
				"https://tailscale.com/kb/1067/update" "Update Tailscale to $MIN_SAFE_VERSION or newer" \
				"Update Tailscale now: ${SUDO}tailscale update (or update it from the Tailscale app or your package manager)." \
				"Turn on automatic updates so it stays current: ${SUDO}tailscale set --auto-update"
		else
			add L C01 WARN "$C1" "Tailscale is up to date, but the \"Tailworm\" problem has no fix yet" \
				"version $VER; Tailworm (Oct 25 2026) is unpatched" \
				"Version $VER is fine, but the Tailworm security problems published on 25 Oct 2026 are not fixed in any Tailscale version yet." \
				"Until a fix is released, your settings are the only protection. The other items in this report are those settings." \
				"https://tailscale.com/security-bulletins" "Keep automatic updates on and watch for the Tailworm fix" \
				"Fix the other problems in this report." \
				"Keep automatic updates on, so the fix installs as soon as it is released." \
				"Check https://tailscale.com/security-bulletins for news of the fix."
		fi
	else
		unknown C01 "$C1" "Could not read the Tailscale version" "'tailscale version' failed: $(ts_err "$TMP/version")" \
			"The 'tailscale version' command failed." "$VSTEP"
	fi

	# status --json is used by checks 2, 6, 11
	progress "Reading tailscale status"
	if run_ts "$TMP/status.json" status --json && json_flat "$TMP/status.json" "$TMP/status.flat"; then
		STATUS_OK=1
		BACKEND=$(jget "$TMP/status.flat" .BackendState || true)
		jhas "$TMP/status.flat" ".Self." && SELF_OK=1
	fi

	# 2. daemon
	C2="Daemon running and logged in"
	BUSY="Most of the other checks could not be done."
	if [ "$STATUS_OK" -ne 1 ]; then
		add L C02 FAIL "$C2" "Tailscale is not running" "'tailscale status --json' failed: $(ts_err "$TMP/status.json")" \
			"The Tailscale service is not running, or the tool could not talk to it." "$BUSY" "" "Start Tailscale and log in" \
			"Start it: sudo systemctl enable --now tailscaled" "Log in: sudo tailscale up" "$AGAIN"
	else
		case "$BACKEND" in
		Running) pass C02 "$C2" "Tailscale is running and logged in" "BackendState=Running" ;;
		NeedsLogin | NeedsMachineAuth)
			add L C02 FAIL "$C2" "Tailscale is not logged in" "BackendState=$BACKEND" \
				"This device is not logged in to your Tailscale network (or is waiting for approval)." "$BUSY" "" "Log in to Tailscale" \
				"Log in: ${SUDO}tailscale up (or log in from the Tailscale app)." \
				"If it waits for approval, approve the device in the admin console." "$AGAIN"
			;;
		Stopped)
			add L C02 FAIL "$C2" "Tailscale is turned off (disconnected)" "BackendState=Stopped" \
				"Tailscale is installed but disconnected." "$BUSY" "" "Connect Tailscale" \
				"Connect: ${SUDO}tailscale up (or click Connect in the Tailscale app)." "$AGAIN"
			;;
		Starting | NoState)
			add L C02 WARN "$C2" "Tailscale is still connecting" "BackendState=$BACKEND" \
				"Tailscale has started but is not connected yet, so a few checks could not be finished." \
				"Those checks show up under COULD NOT CHECK." "" "Wait for Tailscale to connect, then run this check again" \
				"Wait a minute, then run this check again." \
				"If it stays like this, restart it: sudo systemctl restart tailscaled, and check the internet connection."
			;;
		*)
			unknown C02 "$C2" "Could not tell whether Tailscale is connected" "BackendState=$BACKEND" \
				"Tailscale reported an unexpected state: $BACKEND" "Check it by hand: tailscale status"
			;;
		esac
	fi

	# prefs are used by checks 3, 4, 7, 9
	progress "Reading node settings"
	if run_ts "$TMP/prefs.json" debug prefs && json_flat "$TMP/prefs.json" "$TMP/prefs.flat"; then
		PREFS_OK=1
	fi
	pref() { [ "$PREFS_OK" -eq 1 ] && jget "$TMP/prefs.flat" "$1"; }

	# 3. Tailscale SSH server
	C3="Tailscale SSH server"
	SSH_STATE=unknown # used by check 13
	v=$(pref .RunSSH) || v=""
	case "$v" in
	true)
		SSH_STATE=on
		add L C03 WARN "$C3" "Tailscale SSH is turned on for this device" "RunSSH=true" \
			"Other devices in your network can open a remote command line on this device through Tailscale SSH." \
			"This is exactly what the Tailworm attack uses: one hacked device can take full (root) control of this one, then move on to the next." \
			"https://tailscale.com/kb/1193/tailscale-ssh" "Turn off Tailscale SSH on this device if you don't need it" \
			"First make sure you have another way in (sitting at it, or normal SSH)." \
			"If you don't use Tailscale SSH to reach this device, turn it off: ${SUDO}tailscale set --ssh=false" \
			"If you need it, keep the SSH rules in your policy as narrow as possible (one person to this one device), and turn on the SSH forwarding off-switch (see the forwarding check)."
		;;
	false)
		SSH_STATE=off
		pass C03 "$C3" "Tailscale SSH is turned off on this device" "RunSSH=false"
		;;
	*) prefs_unknown C03 "$C3" "Could not check whether Tailscale SSH is on" RunSSH ;;
	esac

	# 4. control server
	C4="Control server"
	IS_HEADSCALE=0
	if v=$(pref .ControlURL); then
		host=${v#*://}
		host=${host%%/*}
		host=${host%%:*}
		case "$host" in
		"" | null | controlplane.tailscale.com | login.tailscale.com)
			pass C04 "$C4" "Managed by Tailscale's official service" "ControlURL=$v"
			;;
		*)
			IS_HEADSCALE=1
			add L C04 WARN "$C4" "Managed by a self-hosted server (headscale?)" "ControlURL=$v" \
				"This device is managed by $v, not by Tailscale's own service." \
				"On headscale, SSH port forwarding can't be turned off from the policy, so anyone allowed to SSH into a device can become its administrator (root)." \
				"" "Treat every SSH permission as full admin access (headscale)" \
				"Treat every SSH permission in your policy as full admin access." \
				"Allow SSH only from one person or device to one server at a time." \
				"On every server that accepts Tailscale SSH, turn on the forwarding off-switch: $FWD_VAR=1 on tailscaled (see the forwarding check)." \
				"For the most important servers, you can instead turn off Tailscale SSH and use normal OpenSSH with 'AllowTcpForwarding no' and 'AllowStreamLocalForwarding no' in sshd_config."
			;;
		esac
	else
		prefs_unknown C04 "$C4" "Could not check which control server is used" ControlURL
	fi

	# 5. Tailnet Lock
	progress "Checking Tailnet Lock"
	C5="Tailnet Lock"
	LSTEP="Run it by hand: tailscale lock status"
	if run_ts "$TMP/lock" lock status; then
		if grep -qi 'not enabled' "$TMP/lock"; then
			hs=()
			[ "$IS_HEADSCALE" -eq 1 ] && hs=("Note: headscale may not support Tailnet Lock.")
			add L C05 FAIL "$C5" "Tailnet Lock is turned off" "tailscale lock status: Tailnet Lock is NOT enabled" \
				"If someone gets into your Tailscale account (or Tailscale's servers), they can add their own device to your network, and your devices will trust it." \
				"The Tailworm attack needs only one bad device inside your network to spread to the others." \
				"https://tailscale.com/kb/1226/tailnet-lock" "Turn on Tailnet Lock" \
				"On 2 or more devices you trust, run: tailscale lock status, and copy the 'tlpub:...' key it shows." \
				"On one of them, run: tailscale lock init --gen-disablements 1 --confirm tlpub:KEY1 tlpub:KEY2" \
				"Save the 'disablement secret' it prints somewhere safe and offline. It is the only way to switch the lock off in an emergency." \
				"From then on, approve new devices with: tailscale lock sign" "${hs[@]+"${hs[@]}"}"
		elif grep -qi 'lock is enabled' "$TMP/lock"; then
			pass C05 "$C5" "Tailnet Lock is turned on" "Tailnet Lock is enabled"
		else
			first=$(head -n1 "$TMP/lock" | tr -d '\r')
			unknown C05 "$C5" "Could not check Tailnet Lock" "unrecognised output: $first" \
				"The tool did not understand the output: $first" "$LSTEP"
		fi
	else
		unknown C05 "$C5" "Could not check Tailnet Lock" "'tailscale lock status' failed: $(ts_err "$TMP/lock")" \
			"The 'tailscale lock status' command failed." "$LSTEP"
	fi

	# 6. key expiry
	C6="Node key expiry"
	NOT_RUNNING="Tailscale must be connected to check this (current state: ${BACKEND:-none})."
	CONNECT="Connect Tailscale, then run this check again."
	if [ "$STATUS_OK" -eq 1 ] && [ "$SELF_OK" -eq 1 ] && [ "$BACKEND" = "Running" ]; then
		if v=$(jget "$TMP/status.flat" .Self.KeyExpiry) && [ "$v" != "null" ]; then
			d=$(date -d "$v" '+%d %b %Y' 2>/dev/null | sed 's/^0//') || d=""
			pass C06 "$C6" "This device's login expires normally (next: ${d:-$v})" "KeyExpiry=$v"
		else
			add L C06 WARN "$C6" "This device's login never expires" "no Self.KeyExpiry while Running" \
				"Key expiry is turned off for this device, so it stays in your network forever, even if it is lost or stolen." \
				"A stolen or hacked device keeps its access until someone removes it by hand." \
				"https://tailscale.com/kb/1028/key-expiry" "Turn key expiry back on for this device" \
				"Open https://login.tailscale.com/admin/machines" \
				"Find this device, click its ... menu and choose 'Enable key expiry'."
		fi
	else
		unknown C06 "$C6" "Could not check whether this device's login expires" "state: ${BACKEND:-none}" "$NOT_RUNNING" "$CONNECT"
	fi

	# 7. auto-updates
	C7="Auto-updates"
	upd_off() { # TITLE DETAIL
		add L C07 WARN "$C7" "$1" "$2" \
			"Tailscale will not install security fixes by itself." \
			"When the Tailworm fix is released, this device stays unprotected until someone updates it by hand." \
			"https://tailscale.com/kb/1067/update" "Turn on automatic updates" \
			"Turn on automatic updates: ${SUDO}tailscale set --auto-update"
	}
	if v=$(pref .AutoUpdate.Apply); then
		case "$v" in
		true) pass C07 "$C7" "Automatic updates are on" "AutoUpdate.Apply=true" ;;
		false) upd_off "Automatic updates are off" "AutoUpdate.Apply=false" ;;
		null)
			# Not set on the device: the tailnet-wide default applies (Self.CapMap "default-auto-update").
			def=""
			if [ "$STATUS_OK" -eq 1 ] && [ "$SELF_OK" -eq 1 ]; then
				def=$(jget "$TMP/status.flat" ".Self.CapMap.default-auto-update[0]" || true)
			fi
			case "$def" in
			true) pass C07 "$C7" "Automatic updates are on (tailnet default)" "AutoUpdate.Apply not set; tailnet default-auto-update=true" ;;
			false) upd_off "Automatic updates are off (tailnet default)" "AutoUpdate.Apply not set; tailnet default-auto-update=false" ;;
			*)
				unknown C07 "$C7" "Automatic updates: not set on this device (using the tailnet default)" \
					"AutoUpdate.Apply not set; tailnet default not reported" \
					"This device follows the tailnet-wide default, and the tool couldn't read what that default is." \
					"Turn them on for this device to be sure: ${SUDO}tailscale set --auto-update" \
					"Or check the tailnet-wide auto-update setting in the admin console."
				;;
			esac
			;;
		*)
			unknown C07 "$C7" "Could not check automatic updates" "AutoUpdate.Apply=$v" \
				"Tailscale reported an unexpected value: $v" "Check it by hand: tailscale debug prefs (look for AutoUpdate)."
			;;
		esac
	else
		prefs_unknown C07 "$C7" "Could not check automatic updates" AutoUpdate.Apply
	fi

	# 8. serve Unix-socket targets
	progress "Checking tailscale serve"
	C8="Serve Unix-socket targets"
	if run_ts "$TMP/serve.json" serve status --json; then
		socks=$(grep -oE '"unix:[^"]*"' "$TMP/serve.json" | tr -d '"' | sort -u)
		if [ -n "$socks" ]; then
			add L C08 FAIL "$C8" "'tailscale serve' is sharing a local system socket" "serve targets: $(printf '%s' "$socks" | tr '\n' ' ')" \
				"This device shares $(printf '%s' "$socks" | paste -sd, - | sed 's/,/, /g') with your network through 'tailscale serve'." \
				"System sockets (like docker.sock) give full control of the device, and the Tailworm report shows these shares can be abused." \
				"https://tailscale.com/kb/1312/serve" "Remove the socket share from 'tailscale serve'" \
				"See what is shared: tailscale serve status" \
				"Remove all shares: ${SUDO}tailscale serve reset (or remove just that one share)."
		else
			pass C08 "$C8" "No risky 'tailscale serve' shares" "no unix: targets"
		fi
	else
		unknown C08 "$C8" "Could not check what 'tailscale serve' shares" "'tailscale serve status --json' failed: $(ts_err "$TMP/serve.json")" \
			"The 'tailscale serve status' command failed." "Run it by hand: tailscale serve status"
	fi

	# 9. app connector, subnet routes, exit node
	C9="App connector"
	if v=$(pref .AppConnector.Advertise); then
		if [ "$v" = "true" ]; then
			add L C09 WARN "$C9" "This device is an app connector" "AppConnector.Advertise=true" \
				"This device routes traffic to outside apps or websites for the rest of your network." \
				"The Tailworm report says app connectors can be used to get around your access rules." \
				"https://tailscale.com/kb/1281/app-connectors" "Turn off the app connector if you don't need it" \
				"If you don't need it, turn it off: ${SUDO}tailscale set --advertise-connector=false" \
				"Also remove app connector settings you don't use from your policy file."
		else
			pass C09 "$C9" "This device is not an app connector" "AppConnector.Advertise=$v"
		fi
	else
		prefs_unknown C09 "$C9" "Could not check whether this device is an app connector" AppConnector.Advertise
	fi
	if [ "$PREFS_OK" -eq 1 ] && jhas "$TMP/prefs.flat" .AdvertiseRoutes; then
		routes=$(jlist "$TMP/prefs.flat" .AdvertiseRoutes)
		subnets=$(printf '%s\n' "$routes" | grep -vxE '0\.0\.0\.0/0|::/0' | grep -v '^$' | paste -sd, - | sed 's/,/, /g')
		if [ -n "$subnets" ]; then
			info C09R "Subnet routes" "Shares these local networks with your tailnet: $subnets" "AdvertiseRoutes" \
				"Devices allowed by your policy can reach these networks through this device."
		else
			info C09R "Subnet routes" "Does not share any local networks (subnet routes)" "AdvertiseRoutes: none"
		fi
		if printf '%s\n' "$routes" | grep -qxE '0\.0\.0\.0/0|::/0'; then
			info C09E "Exit node" "Is an exit node (other devices can send their internet traffic through it)" "AdvertiseRoutes has 0.0.0.0/0"
		else
			info C09E "Exit node" "Is not an exit node" "no 0.0.0.0/0 route"
		fi
	else
		prefs_unknown C09R "Subnet routes" "Could not check shared networks or exit node" AdvertiseRoutes
	fi

	# 11. blast radius (the peer list is only complete while Running)
	C11="Peers with Tailscale SSH"
	if [ "$STATUS_OK" -eq 1 ] && [ "$SELF_OK" -eq 1 ] && [ "$BACKEND" = "Running" ]; then
		awk -F'\t' '$1 ~ /^\.Peer\.[^.]+\.sshHostKeys\[0\]$/ { k = $1; sub(/^\.Peer\./, "", k); sub(/\.sshHostKeys\[0\]$/, "", k); print k }' "$TMP/status.flat" >"$TMP/sshpeers"
		npeers=$(awk -F'\t' '$1 ~ /^\.Peer\.[^.]+\.HostName$/' "$TMP/status.flat" | wc -l | tr -d ' ')
		nssh=$(wc -l <"$TMP/sshpeers" | tr -d ' ')
		: >"$TMP/sshnames"
		while IFS= read -r k; do
			jget "$TMP/status.flat" ".Peer.$k.HostName" >>"$TMP/sshnames" || echo "$k" >>"$TMP/sshnames"
		done <"$TMP/sshpeers"
		names=$(sort "$TMP/sshnames" | paste -sd, - | sed 's/,/, /g')
		if [ "$nssh" -gt 0 ]; then
			note="These are the devices an attacker could try to reach with Tailworm: $names. Turn off Tailscale SSH on any that don't need it (tailscale set --ssh=false on that device)."
		else
			note="None of your other devices accept Tailscale SSH, so Tailworm has nothing to attack from here right now."
		fi
		info C11 "$C11" "$nssh of your $npeers other devices accept Tailscale SSH" "$nssh of $npeers peers have sshHostKeys" "$note"
	else
		unknown C11 "$C11" "Could not count devices that accept Tailscale SSH" "state: ${BACKEND:-none}" "$NOT_RUNNING" "$CONNECT"
	fi

	# 13. TS_SSH_DISABLE_FORWARDING on the running tailscaled. It is read by
	# tailscaled (ssh/tailssh envknob) and checked before the policy in every TCP
	# and Unix-socket forwarding callback; undocumented, a stopgap for Tailworm.
	# TAILGUARD_FWD_ROOT (tests) replaces "/": ROOT/environ stands for the
	# daemon's environment and config files are read under ROOT/etc/...
	FWD_FOUND=0 FWD_READ=0 FWD_ACTIVE=0 FWD_CONF=""
	if [ -n "${TAILGUARD_FWD_ROOT:-}" ]; then
		froot=$TAILGUARD_FWD_ROOT
		if [ -e "$froot" ]; then
			FWD_FOUND=1
			if [ -f "$froot/environ" ] && [ -r "$froot/environ" ]; then
				FWD_READ=1
				fwd_from_env "$froot/environ" && FWD_ACTIVE=1
			fi
		fi
	else
		froot=""
		for c in /proc/[0-9]*/comm; do
			[ "$(cat "$c" 2>/dev/null)" = tailscaled ] || continue
			FWD_FOUND=1
			if [ -r "${c%/comm}/environ" ] && tr '\0' '\n' <"${c%/comm}/environ" >"$TMP/fwdenv" 2>/dev/null; then
				FWD_READ=1
				fwd_from_env "$TMP/fwdenv" && FWD_ACTIVE=1
			fi
			break
		done
	fi
	for c in "$froot/etc/default/tailscaled" "$froot/etc/sysconfig/tailscaled" \
		"$froot"/etc/systemd/system/tailscaled.service.d/*.conf \
		"$froot"/run/systemd/system/tailscaled.service.d/*.conf \
		"$froot"/lib/systemd/system/tailscaled.service.d/*.conf; do
		[ -f "$c" ] && [ -r "$c" ] && fwd_from_conf "$c" && FWD_CONF=$c
	done
	C13="SSH forwarding off-switch"
	FWD_HELP="https://github.com/tailscale/tailscale/blob/main/ssh/tailssh/tailssh.go"
	FWD_S1="First make sure you have another way in (console or normal SSH) in case tailscaled doesn't come back."
	FWD_S3="Restart it: sudo systemctl daemon-reload && sudo systemctl restart tailscaled"
	if [ "$FWD_READ" -eq 1 ] && [ "$FWD_ACTIVE" -eq 1 ]; then
		pass C13 "$C13" "SSH forwarding off-switch is on ($FWD_VAR)" "running tailscaled has $FWD_VAR set to true"
	elif [ "$FWD_READ" -eq 1 ] && [ -n "$FWD_CONF" ]; then
		add L C13 WARN "$C13" "SSH forwarding off-switch is set but not active yet" \
			"set in $FWD_CONF; not in the running tailscaled's environment" \
			"It is set in $FWD_CONF, but the running tailscaled doesn't have it, so forwarding is still allowed." \
			"The setting only takes effect when tailscaled starts." \
			"$FWD_HELP" "Restart tailscaled so the forwarding off-switch takes effect" \
			"$FWD_S1" "$FWD_S3" "Run this check again to confirm."
	elif [ "$FWD_READ" -eq 1 ] && [ "$SSH_STATE" = on ]; then
		add L C13 WARN "$C13" "Tailscale SSH is on and SSH forwarding is allowed" \
			"$FWD_VAR not set in the running tailscaled" \
			"This device accepts Tailscale SSH and nothing on the device blocks port forwarding through it." \
			"Tailworm uses SSH port forwarding to reach hidden services on the device and become root." \
			"$FWD_HELP" "Turn on the SSH forwarding off-switch on this server" \
			"$FWD_S1" \
			"Create the file /etc/systemd/system/tailscaled.service.d/50-disable-ssh-forwarding.conf with two lines: [Service] and Environment=$FWD_VAR=1" \
			"$FWD_S3" \
			"Note: this is an undocumented Tailscale setting (a stopgap until the fix ships). It blocks TCP and Unix-socket forwarding, not SSH agent forwarding."
	elif [ "$SSH_STATE" = off ]; then
		# Nothing to forward through, whether or not tailscaled could be inspected.
		info C13 "$C13" "SSH forwarding off-switch: not needed now (Tailscale SSH is off)" "$FWD_VAR not active" \
			"If you ever turn Tailscale SSH on for this device, turn this switch on too."
	elif [ "$FWD_FOUND" -eq 0 ]; then
		unknown C13 "$C13" "Could not check the SSH forwarding off-switch" "tailscaled process not found" \
			"The tailscaled process wasn't found, so its settings couldn't be read." \
			"Make sure tailscaled is running: sudo systemctl status tailscaled" "Then run this check again with sudo."
	elif [ "$FWD_READ" -eq 0 ]; then
		problem="The running tailscaled's settings can only be read with admin rights."
		[ -n "$FWD_CONF" ] && problem="$problem It is set in $FWD_CONF, but whether tailscaled has picked it up is unknown."
		unknown C13 "$C13" "Could not check the SSH forwarding off-switch" "tailscaled environment not readable (not root)" \
			"$problem" "Run this check again with sudo."
	else
		unknown C13 "$C13" "Could not check the SSH forwarding off-switch" "$FWD_VAR not set; RunSSH unknown" \
			"The forwarding off-switch isn't set, and the tool couldn't tell whether Tailscale SSH is on." \
			"Check by hand: tailscale debug prefs (look for RunSSH)." "If it is true, turn on the off-switch as described in the README."
	fi
fi

# 10. auth keys on disk (works without the tailscale CLI too)
if [ -n "${TAILGUARD_SCAN_ROOTS:-}" ]; then
	IFS=: read -r -a SCAN <<<"$TAILGUARD_SCAN_ROOTS"
else
	SCAN=(/etc /lib/systemd/system /usr/lib/systemd/system /var/spool/cron /var/spool/cron/crontabs
		/root /usr/local/bin /usr/local/sbin /opt/scripts)
	for f in /home/*/.bash_history /home/*/.zsh_history /home/*/.ash_history /home/*/.profile \
		/home/*/.bashrc /home/*/*.sh /home/*/bin /root/.bash_history /root/.ash_history; do
		[ -e "$f" ] && SCAN+=("$f")
	done
fi
GREP_I=""
grep -I x /dev/null >/dev/null 2>&1
[ $? -le 1 ] && GREP_I="-I"
: >"$TMP/keys"
# 60 s per folder, like the Go tool, so a huge /root can't make it look stuck.
LIMIT=()
timeout 1 true >/dev/null 2>&1 && LIMIT=(timeout 60)
SCAN_INCOMPLETE=()
progress "Scanning for auth keys"
for p in "${SCAN[@]}"; do
	[ -e "$p" ] || continue
	progress_detail "$p"
	if [ ! -r "$p" ]; then
		SKIPPED+=("$p")
		continue
	fi
	# shellcheck disable=SC2086 # GREP_I is empty or one flag
	"${LIMIT[@]+"${LIMIT[@]}"}" grep -rsoE $GREP_I --exclude-dir=.cache --exclude-dir=node_modules --exclude-dir=.git \
		'tskey-[A-Za-z0-9_-]{8,}' "$p" >>"$TMP/keys" 2>/dev/null
	# grep itself only exits 0, 1 or 2. Anything higher means the limit hit:
	# GNU timeout exits 124, BusyBox's kills grep with TERM (shell sees 143).
	[ $? -gt 2 ] && SCAN_INCOMPLETE+=("$p")
done
if [ "$IS_ROOT" -eq 0 ] && [ -z "${TAILGUARD_SCAN_ROOTS:-}" ]; then
	SKIPPED+=("unreadable files under /etc /root /var/spool/cron (not root)")
fi
if [ "${#SCAN_INCOMPLETE[@]}" -gt 0 ]; then
	inc=$(printf '%s, ' "${SCAN_INCOMPLETE[@]}")
	SKIPPED+=("auth-key scan hit the 1m0s limit in ${inc%, }")
fi
C10="Auth keys on disk"
if [ -s "$TMP/keys" ]; then
	hits=""
	nhits=0
	while IFS= read -r line; do
		file=${line%%:tskey-*}
		key=${line#"$file":}
		hits="${hits:+$hits; }$file: $(mask_key "$key")"
		nhits=$((nhits + 1))
	done < <(sort -u "$TMP/keys")
	add L C10 WARN "$C10" "Tailscale login keys found saved in files" "$nhits tskey- match(es), shown masked above" \
		"$nhits Tailscale auth key(s) are saved in plain text in these files: $hits" \
		"Anyone who can read these files can use the key to add their own device to your network." \
		"https://tailscale.com/kb/1085/auth-keys" "Revoke and delete the saved Tailscale login keys" \
		"Revoke each key in the admin console: https://login.tailscale.com/admin/settings/keys" \
		"Delete the key from the files listed above." \
		"Next time, use a one-off or ephemeral key, or keep keys in a password or secret manager."
elif [ "${#SCAN_INCOMPLETE[@]}" -gt 0 ]; then
	inc=$(printf '%s, ' "${SCAN_INCOMPLETE[@]}")
	unknown C10 "$C10" "The search for saved login keys did not finish" "none found, but the scan did not finish in: ${inc%, }" \
		"No keys were found, but these folders were too big to search completely: ${inc%, }" \
		"Search them by hand (this can take a while): sudo grep -rl 'tskey-' ${SCAN_INCOMPLETE[*]}" \
		"If it finds anything other than this tool's own test files, revoke and delete those keys."
else
	pass C10 "$C10" "No Tailscale login keys found saved in files" "no tskey- strings found in the searched paths"
fi

# 12. privileges
C12="Running with admin rights"
if [ "$IS_ROOT" -eq 1 ]; then
	info C12 "$C12" "Ran with admin rights, so every location was checked" "elevated: yes"
else
	sk=$(printf '%s, ' "${SKIPPED[@]+"${SKIPPED[@]}"}")
	sk=${sk%, }
	info C12 "$C12" "Ran without admin rights, so some places could not be searched" "elevated: no; skipped: ${sk:-nothing}" \
		"Run it again with sudo for a complete check."
fi

# ---------------------------------------------------------------- policy audit
is_broad() { # value -> true for selectors that always cover many people or devices
	case "$1" in
	"*" | autogroup:member | autogroup:tagged | group:*) return 0 ;;
	esac
	return 1
}

# is_tag VALUE -> one tag is a single pair only if exactly one device carries
# it, which the policy file can't show, so it is a WARN, not a FAIL.
is_tag() { case "$1" in tag:*) return 0 ;; esac; return 1; }

# plain_name VALUE [dst] -> the selector in words
plain_name() {
	case "$1" in
	"*") if [ "${2:-}" = dst ]; then echo "any device"; else echo "anyone"; fi ;;
	autogroup:member) echo "every user in your network" ;;
	autogroup:self) echo "their own devices" ;;
	autogroup:tagged) echo "every tagged device" ;;
	autogroup:admin) echo "admins" ;;
	group:*) echo "everyone in group '${1#group:}'" ;;
	tag:*) echo "every device tagged '${1#tag:}'" ;;
	*) echo "$1" ;;
	esac
}

# join_words SEP-LAST ITEM... -> "a, b and c"
join_words() {
	local last=$1
	shift
	case $# in
	0) return ;;
	1) printf '%s' "$1" ;;
	*)
		local out="" i=1 x
		for x in "$@"; do
			if [ "$i" -eq $# ]; then out="$out $last $x"; elif [ "$i" -eq 1 ]; then out=$x; else out="$out, $x"; fi
			i=$((i + 1))
		done
		printf '%s' "$out"
		;;
	esac
}

plain_list() { # dst|src ITEM...
	local kind=$1 x
	shift
	[ $# -eq 0 ] && { echo "nobody"; return; }
	local -a w=()
	for x in "$@"; do w+=("$(plain_name "$x" "$kind")"); done
	join_words and "${w[@]}"
}

plain_users() {
	local x
	[ $# -eq 0 ] && { echo "no account"; return; }
	local -a w=()
	for x in "$@"; do
		case "$x" in
		root) w+=("root (full admin)") ;;
		autogroup:nonroot) w+=("any normal account") ;;
		"*") w+=("any account") ;;
		*) w+=("'$x'") ;;
		esac
	done
	join_words or "${w[@]}"
}

plain_action() {
	case "$1" in
	check) echo "after confirming their login (check mode)" ;;
	accept) echo "with no extra check (accept mode)" ;;
	*) echo "with action '$1'" ;;
	esac
}

padd() { add P "$@"; }

FWD_NOTE="Tailscale's policy reference (kb/1337, kb/1193) documents no ssh-rule forwarding field. The node protocol carries per-rule flags (tailcfg.SSHAction allowLocalPortForwarding / allowRemotePortForwarding); reports say the hosted service can set them per rule, but that is undocumented. Host-level switch: TS_SSH_DISABLE_FORWARDING on tailscaled (in Tailscale's source, undocumented)."

if [ -n "$POLICY_FILE" ]; then
	progress "Auditing policy file"
	[ -r "$POLICY_FILE" ] || die "cannot read policy file: $POLICY_FILE"
	tr -d '\r' <"$POLICY_FILE" | awk "$AWK_HUJSON" >"$TMP/policy.json"
	json_flat "$TMP/policy.json" "$TMP/policy.flat" || die "policy file is not valid HuJSON/JSON: $POLICY_FILE"
	PF="$TMP/policy.flat"

	idx=$(jindexes "$PF" .ssh)
	if [ -z "$idx" ]; then
		padd P-SSH INFO "SSH rules" "Your policy has no SSH rules, so Tailworm has nothing to use" "no rules in the \"ssh\" section" "" "" "" ""
	fi
	ja() { local o="" x; for x in "$@"; do o="$o\"$(json_esc "$x")\","; done; printf '[%s]' "${o%,}"; }
	for i in $idx; do
		n=$((i + 1))
		mapfile -t src < <(jlist "$PF" ".ssh[$i].src")
		mapfile -t dst < <(jlist "$PF" ".ssh[$i].dst")
		mapfile -t users < <(jlist "$PF" ".ssh[$i].users")
		action=$(jget "$PF" ".ssh[$i].action" || echo "(none)")
		s_txt=$(printf '%s, ' "${src[@]+"${src[@]}"}")
		d_txt=$(printf '%s, ' "${dst[@]+"${dst[@]}"}")
		u_txt=$(printf '%s, ' "${users[@]+"${users[@]}"}")
		s_txt=${s_txt%, } d_txt=${d_txt%, } u_txt=${u_txt%, }
		who=$(plain_list src "${src[@]+"${src[@]}"}")
		where=$(plain_list dst "${dst[@]+"${dst[@]}"}")
		summary="SSH rule $n: $who can log in to $where as $(plain_users "${users[@]+"${users[@]}"}"), $(plain_action "$action")."
		RULE_SUMMARY+=("$summary")
		RULE_JSON+=("{\"index\": $n, \"src\": $(ja "${src[@]+"${src[@]}"}"), \"dst\": $(ja "${dst[@]+"${dst[@]}"}"), \"users\": $(ja "${users[@]+"${users[@]}"}"), \"action\": \"$(json_esc "$action")\", \"summary\": \"$(json_esc "$summary")\"}")

		# broad lists everything wide (tags too, for the details line); hard is
		# set by anything other than a single tag, which makes the rule a FAIL.
		broad="" tags="" hard=0
		for x in "${src[@]+"${src[@]}"}"; do
			if is_broad "$x"; then broad="$broad src:$x" hard=1; elif is_tag "$x"; then broad="$broad src:$x" tags="$tags src:$x"; fi
		done
		for x in "${dst[@]+"${dst[@]}"}"; do
			if is_broad "$x"; then broad="$broad dst:$x" hard=1; elif is_tag "$x"; then broad="$broad dst:$x" tags="$tags dst:$x"; fi
		done
		[ "${#src[@]}" -gt 1 ] && broad="$broad ${#src[@]}-sources" hard=1
		[ "${#dst[@]}" -gt 1 ] && broad="$broad ${#dst[@]}-destinations" hard=1
		if [ "$hard" -eq 0 ] && [ -n "$tags" ]; then
			padd "P-SSH-$n-TAG" WARN "ssh rule #$n uses a tag" "SSH rule $n uses a tag: make sure only one device has it" \
				"src=[$s_txt] dst=[$d_txt]; tag:$tags" \
				"It lets $who log in to $where. That is a single person-to-device pair only if exactly one device has this tag." \
				"If several devices share the tag, one hacked device can use this rule to reach all of them." \
				"" "Check that the tag in SSH rule $n is on only one device" \
				"In the admin console (Machines), filter by this tag and check that only one device has it." \
				"If several do, give the server its own tag (for example tag:web-01) and use that in this rule."
		fi
		if [ "$hard" -eq 1 ]; then
			problem="It lets $who log in to $where."
			if [ "${#dst[@]}" -eq 1 ] && [ "${dst[0]}" = "autogroup:self" ]; then
				problem="$problem Each person can only reach devices they own, so this is Tailscale's default and lower risk than most broad rules, but it is still more than one person-to-device pair."
			fi
			padd "P-SSH-$n-BROAD" FAIL "ssh rule #$n is broad" "SSH rule $n is too broad" "src=[$s_txt] dst=[$d_txt]; broad:$broad" \
				"$problem" \
				"If any one of those devices is hacked, the attacker can use this rule to get into the others. This is how Tailworm spreads." \
				"" "Delete or narrow SSH rule $n" \
				"If you don't use Tailscale SSH (see the 'devices accept Tailscale SSH' line in this report), delete this rule from the \"ssh\" section of your policy." \
				"If you do use it, replace it with one rule for each person and the one device they need, for example: {\"action\": \"check\", \"src\": [\"you@example.com\"], \"dst\": [\"tag:my-server\"], \"users\": [\"autogroup:nonroot\"]}" \
				"A rule with one person and one tag like this only gets a lighter warning, as long as exactly one device has that tag."
		fi
		for x in "${users[@]+"${users[@]}"}"; do
			if [ "$x" = "root" ]; then
				padd "P-SSH-$n-ROOT" WARN "ssh rule #$n allows root" "SSH rule $n allows logging in as root" "users=[$u_txt]" \
					"The rule's \"users\" list includes \"root\", the all-powerful admin account." \
					"Anyone who gets in through this rule has full control of the device straight away." \
					"" "Remove root from SSH rule $n" \
					"Remove \"root\" from the \"users\" list (keep \"autogroup:nonroot\")." \
					"Log in as a normal user and use sudo when you need admin rights."
				break
			fi
		done
		if [ "$action" = "accept" ]; then
			padd "P-SSH-$n-ACCEPT" WARN "ssh rule #$n uses accept" "SSH rule $n doesn't ask users to confirm their login" "action=accept" \
				"The rule uses \"action\": \"accept\", so SSH connects without any extra check." \
				"A hacked device can use this rule straight away, without anyone noticing." \
				"" "Change SSH rule $n to check mode" \
				"Change \"action\": \"accept\" to \"action\": \"check\"." \
				"Optionally add \"checkPeriod\": \"1h\" so the confirmation is asked again every hour."
		fi
		GROUP=fwd REF="SSH rule $n"
		padd "P-SSH-$n-FWD" WARN "ssh rule #$n cannot disable port forwarding" "SSH port forwarding isn't controlled by any documented policy setting" "$FWD_NOTE" \
			"Tailscale's documented policy settings can't block SSH port forwarding (checked 26-27 Oct 2026). Reports say the hosted service has a per-rule switch, but it isn't documented yet." \
			"So assume anyone these SSH rules let in can tunnel to hidden services on the device. Tailworm uses this to become root." \
			"" "Keep SSH rules narrow and turn on the SSH forwarding off-switch on servers" \
			"Treat every SSH rule as if it gives full admin access, and keep each one as narrow as possible." \
			"On every Linux server that accepts Tailscale SSH, turn on the forwarding off-switch: $FWD_VAR=1 on tailscaled (see the forwarding check when you run this tool there)." \
			"For the most important servers, you can instead turn off Tailscale SSH (${SUDO}tailscale set --ssh=false) and use normal OpenSSH with 'AllowTcpForwarding no' and 'AllowStreamLocalForwarding no' in sshd_config." \
			"You can ignore this warning if the forwarding check (C13) shows PASS on every Linux server these SSH rules reach. The policy file can't see your servers, so this warning always appears."
		GROUP="" REF=""
	done

	for sect in nodeAttrs grants; do
		for i in $(jindexes "$PF" ".$sect"); do
			if awk -F'\t' -v p=".${sect}[$i]" 'index($1, p) == 1 && index($1, "tailscale.com/app-connectors") { f = 1; exit } END { exit !f }' "$PF"; then
				n=$((i + 1))
				padd "P-APPC-$sect-$n" WARN "app connector grant in $sect #$n" "Your policy turns on app connectors (\"$sect\" entry $n)" \
					"$sect #$n has tailscale.com/app-connectors" \
					"This entry gives devices the app connector feature (tailscale.com/app-connectors)." \
					"The Tailworm report says app connectors can be used to get around your access rules." \
					"" "Remove the app connector entry from your policy if you don't use it" \
					"If you don't use app connectors, delete this entry." \
					"If you do, limit it to the one or two devices that really need it."
			fi
		done
	done

	OWN="Replace it with rules for what you actually use. A safe start is letting each person reach only their own devices: "
	LOCKOUT="Add a \"tests\" section and use Preview before saving, so you don't lock yourself out of a device."
	ALLWHY="One hacked device can then reach every service on every other device in your network."
	for i in $(jindexes "$PF" .acls); do
		if jlist "$PF" ".acls[$i].src" | grep -qx '\*' && jlist "$PF" ".acls[$i].dst" | grep -qx '\*:\*'; then
			n=$((i + 1))
			padd "P-ACL-$n-ALLOWALL" WARN "acl #$n allows everything" "Access rule $n lets every device reach every port on every other device" \
				"acls: src * -> dst *:*" "This \"acls\" entry is the 'allow everything' rule (\"*\" to \"*:*\")." "$ALLWHY" \
				"" "Replace the allow-everything access rule with specific rules" \
				"$OWN{\"action\": \"accept\", \"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:self:*\"]}" \
				"Then add one rule for each shared server and the ports people need on it." "$LOCKOUT"
		fi
	done
	for i in $(jindexes "$PF" .grants); do
		if jlist "$PF" ".grants[$i].src" | grep -qx '\*' && jlist "$PF" ".grants[$i].dst" | grep -qx '\*' && jlist "$PF" ".grants[$i].ip" | grep -qx '\*'; then
			n=$((i + 1))
			padd "P-GRANT-$n-ALLOWALL" WARN "grant #$n allows everything" "Grant $n lets every device reach every port on every other device" \
				"grants: src * -> dst * ip *" "This \"grants\" entry is the 'allow everything' rule (\"*\" to \"*\" on all ports). It is Tailscale's default." "$ALLWHY" \
				"" "Replace the allow-everything grant with specific grants" \
				"$OWN{\"src\": [\"autogroup:member\"], \"dst\": [\"autogroup:self\"], \"ip\": [\"*\"]}" \
				"Then add one grant for each shared server and the ports people need on it." "$LOCKOUT"
		fi
	done
fi

# ---------------------------------------------------------------- report
declare -A COUNT=([PASS]=0 [WARN]=0 [FAIL]=0 [INFO]=0 [UNKNOWN]=0)
for s in "${F_STATUS[@]}"; do
	COUNT[$s]=$((COUNT[$s] + 1))
done

# Cards: local findings in check order, then policy findings; findings that
# share a GROUP become one card whose title lists every REF.
CARD_IDX=() CARD_TITLE=()
declare -A GROUP_AT=() GROUP_REFS=()
for i in $(for j in "${!F_ID[@]}"; do k=P; [ "${F_KIND[$j]}" = L ] && k=${F_ID[$j]:0:3}; printf '%s %s %s\n' "${F_KIND[$j]}" "$k" "$j"; done | sort -s -k1,1 -k2,2 | awk '{print $3}'); do
	g=${F_GROUP[$i]}
	if [ -n "$g" ] && [ -n "${GROUP_AT[$g]+x}" ]; then
		GROUP_REFS[$g]="${GROUP_REFS[$g]}, ${F_REF[$i]#SSH rule }"
		continue
	fi
	[ -n "$g" ] && GROUP_AT[$g]=${#CARD_IDX[@]} GROUP_REFS[$g]=${F_REF[$i]}
	CARD_IDX+=("$i")
	CARD_TITLE+=("${F_TITLE[$i]}")
done
for g in "${!GROUP_AT[@]}"; do
	r=${GROUP_REFS[$g]}
	case "$r" in *,*) r=${r/SSH rule/SSH rules} ;; esac
	CARD_TITLE[${GROUP_AT[$g]}]="${CARD_TITLE[${GROUP_AT[$g]}]} ($r)"
done

cards_with() { # STATUS -> card numbers (positions in CARD_IDX)
	local c
	for c in "${!CARD_IDX[@]}"; do
		[ "${F_STATUS[${CARD_IDX[$c]}]}" = "$1" ] && echo "$c"
	done
}

# NEXT STEPS: one short action per problem, FAIL first.
TODO=()
num=0
for st in FAIL WARN; do
	for c in $(cards_with "$st"); do
		num=$((num + 1))
		i=${CARD_IDX[$c]}
		do=${F_NEXT[$i]:-${CARD_TITLE[$c]}}
		TODO+=("$do (see $num)")
	done
done
[ -n "$(cards_with UNKNOWN)" ] && TODO+=("Look at the COULD NOT CHECK items and check them by hand")
[ -z "$POLICY_FILE" ] && TODO+=("Also check your access rules: copy your policy from the admin console (Access controls > JSON editor) into a file and run this tool with --policy FILE")
[ "${#TODO[@]}" -gt 0 ] && TODO+=("When you are done, run this check again to confirm everything is fixed")

HOST=$(hostname 2>/dev/null || uname -n)
DATE=$(date +%Y-%m-%d)
NOW=$(date '+%Y-%m-%d %H:%M:%S %Z')
NOW_NICE=$(date '+%d %b %Y %H:%M' | sed 's/^0//')

# para PREFIX INDENT TEXT [COLOUR] -> TEXT wrapped to $WIDTH after PREFIX,
# continuation lines start with INDENT. Colour codes don't count as width.
para() {
	P1=$1 P2=$2 T=$3 CC=${4:-} CO=${4:+$C_OFF} W=$WIDTH awk 'BEGIN {
		p1 = ENVIRON["P1"]; p2 = ENVIRON["P2"]; t = ENVIRON["T"]; cc = ENVIRON["CC"]; co = ENVIRON["CO"]; w = ENVIRON["W"] + 0
		v1 = p1; gsub(/\033\[[0-9;]*m/, "", v1); v2 = p2; gsub(/\033\[[0-9;]*m/, "", v2)
		n = split(t, ws, /[ \t\n]+/); line = ""; pre = p1; lim = w - length(v1)
		for (i = 1; i <= n; i++) {
			if (ws[i] == "") continue
			if (line == "") line = ws[i]
			else if (length(line) + 1 + length(ws[i]) <= lim) line = line " " ws[i]
			else { print pre cc line co; pre = p2; lim = w - length(v2); line = ws[i] }
		}
		if (line != "") print pre cc line co
	}'
}

spaces() { printf '%*s' "$1" ''; }

colour() {
	case "$1" in
	FAIL) printf '%s' "$C_FAIL" ;; WARN) printf '%s' "$C_WARN" ;; PASS) printf '%s' "$C_PASS" ;;
	INFO) printf '%s' "$C_INFO" ;; *) printf '%s' "$C_UNK" ;;
	esac
}

marker() {
	case "$1" in
	FAIL) echo "[X]" ;; WARN) echo "[!]" ;; UNKNOWN) echo "[?]" ;; PASS) echo "[OK]" ;; *) echo "[i]" ;;
	esac
}

heading() { # TITLE COUNT|- COLOUR
	local h=$1 n
	[ "$2" != "-" ] && h="$1 ($2)"
	n=$((WIDTH - 2))
	[ "$n" -gt 62 ] && n=62
	printf '\n %s%s%s%s\n %s\n' "$3" "$C_BOLD" "$h" "$C_OFF" "$(spaces "$n" | tr ' ' '-')"
}

label() { # NAME TEXT
	[ -n "$2" ] && para "     $1" "$(spaces $((5 + ${#1})))" "$2"
	return 0
}

card() { # NUMBER CARD
	local n=$1 i=${CARD_IDX[$2]} st head k=0 s p letters=abcdefghijklmnop
	st=${F_STATUS[$i]}
	head=" $(marker "$st") $n. "
	para "$head" "$(spaces ${#head})" "${CARD_TITLE[$2]}" "$(colour "$st")$C_BOLD"
	label "Problem: " "${F_PROBLEM[$i]}"
	label "Why it matters: " "${F_WHY[$i]}"
	if [ -n "${F_STEPS[$i]}" ]; then
		echo "     How to fix:"
		while IFS= read -r -d "$US" s; do
			p="       ${letters:$k:1}) "
			para "$p" "$(spaces ${#p})" "$s"
			k=$((k + 1))
		done <<<"${F_STEPS[$i]}$US"
	fi
	label "More help: " "${F_HELP[$i]}"
	label "Details: " "${F_DETAIL[$i]}"
	echo
}

report_txt() {
	local bar res=() nf nw nu np c n=0 admin pol i s
	nf=$(cards_with FAIL | wc -l | tr -d ' ')
	nw=$(cards_with WARN | wc -l | tr -d ' ')
	nu=$(cards_with UNKNOWN | wc -l | tr -d ' ')
	np=$(cards_with PASS | wc -l | tr -d ' ')
	bar=$(spaces $((WIDTH < 64 ? WIDTH : 64)) | tr ' ' '=')
	echo "$bar"
	para " " "   " "TAILSCALE SECURITY CHECK  -  $HOST  -  $NOW_NICE" "$C_BOLD"
	if [ "$nf" -gt 0 ]; then
		if [ "$nf" -eq 1 ]; then res+=("${C_FAIL}1 problem to fix now$C_OFF"); else res+=("${C_FAIL}$nf problems to fix now$C_OFF"); fi
	fi
	[ "$nw" -gt 0 ] && res+=("${C_WARN}$nw to review$C_OFF")
	[ "$nu" -gt 0 ] && res+=("${C_UNK}$nu could not be checked$C_OFF")
	res+=("${C_PASS}$np OK$C_OFF")
	[ $((nf + nw)) -eq 0 ] && res=("${C_PASS}No problems found$C_OFF" "${res[@]}")
	s=$(printf '%s  |  ' "${res[@]}")
	printf ' RESULT: %s%s%s\n' "$C_BOLD" "${s%  |  }" "$C_OFF"
	if [ "$IS_ROOT" -eq 1 ]; then admin="yes"; else admin="no (some places were skipped)"; fi
	pol=${POLICY_FILE:-"not checked (add --policy FILE to check your access rules)"}
	para " Admin rights: " "               " "$admin"
	para " Policy file:  " "               " "$pol"
	echo "$bar"
	para " " " " "How to read this: [X] = a real problem, fix it soon. [!] = a risk worth fixing. [?] = could not be checked. [OK] = fine. [i] = for your information."

	if [ "$nf" -gt 0 ]; then
		heading "FIX NOW" "$nf" "$C_FAIL"
		for c in $(cards_with FAIL); do n=$((n + 1)); card "$n" "$c"; done
	fi
	if [ "$nw" -gt 0 ]; then
		heading "REVIEW" "$nw" "$C_WARN"
		for c in $(cards_with WARN); do n=$((n + 1)); card "$n" "$c"; done
	fi
	if [ "$nu" -gt 0 ]; then
		heading "COULD NOT CHECK" "$nu" "$C_UNK"
		for c in $(cards_with UNKNOWN); do n=$((n + 1)); card "$n" "$c"; done
	fi
	if [ "$np" -gt 0 ]; then
		heading "ALL GOOD" "$np" "$C_PASS"
		for c in $(cards_with PASS); do para " ${C_PASS}[OK]$C_OFF " "      " "${CARD_TITLE[$c]}"; done
	fi
	if [ -n "$(cards_with INFO)" ]; then
		heading "FOR YOUR INFORMATION" - "$C_INFO"
		for c in $(cards_with INFO); do
			i=${CARD_IDX[$c]}
			para " ${C_INFO}[i]$C_OFF  " "      " "${CARD_TITLE[$c]}"
			[ -n "${F_PROBLEM[$i]}" ] && para "      " "      " "${F_PROBLEM[$i]}"
		done
	fi
	if [ "${#RULE_SUMMARY[@]}" -gt 0 ]; then
		heading "YOUR SSH RULES, IN PLAIN WORDS" - "$C_BOLD"
		for s in "${RULE_SUMMARY[@]}"; do para " - " "   " "$s"; done
	fi
	heading "NEXT STEPS" - "$C_BOLD"
	if [ "${#TODO[@]}" -eq 0 ]; then
		para " " " " "Nothing to do. Keep Tailscale updated and run this check again after you change your settings."
	fi
	for i in "${!TODO[@]}"; do
		s=" $((i + 1)). "
		para "$s" "$(spaces ${#s})" "${TODO[$i]}."
	done
}

finding_json() { # INDEX
	local i=$1 o s sep=""
	o="{\"id\": \"$(json_esc "${F_ID[$i]}")\", \"status\": \"${F_STATUS[$i]}\", \"check\": \"$(json_esc "${F_CHECK[$i]}")\""
	o="$o, \"detail\": \"$(json_esc "${F_DETAIL[$i]}")\", \"fix\": \"$(json_esc "${F_FIX[$i]}")\", \"title\": \"$(json_esc "${F_TITLE[$i]}")\""
	[ -n "${F_PROBLEM[$i]}" ] && o="$o, \"problem\": \"$(json_esc "${F_PROBLEM[$i]}")\""
	[ -n "${F_WHY[$i]}" ] && o="$o, \"why\": \"$(json_esc "${F_WHY[$i]}")\""
	if [ -n "${F_STEPS[$i]}" ]; then
		o="$o, \"steps\": ["
		while IFS= read -r -d "$US" s; do o="$o$sep\"$(json_esc "$s")\""; sep=", "; done <<<"${F_STEPS[$i]}$US"
		o="$o]"
	fi
	[ -n "${F_HELP[$i]}" ] && o="$o, \"more_help\": \"$(json_esc "${F_HELP[$i]}")\""
	[ -n "${F_NEXT[$i]}" ] && o="$o, \"next_step\": \"$(json_esc "${F_NEXT[$i]}")\""
	printf '%s}' "$o"
}

report_json() {
	local i sep
	printf '{\n  "tool": "tailguard tailscale-audit.sh",\n  "version": "%s",\n' "$TOOL_VERSION"
	printf '  "host": "%s",\n  "date": "%s",\n  "os": "linux",\n  "elevated": %s,\n  "json_backend": "%s",\n' \
		"$(json_esc "$HOST")" "$(json_esc "$NOW")" "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)" "$JSON_BACKEND"
	printf '  "summary": {"PASS": %d, "WARN": %d, "FAIL": %d, "INFO": %d, "UNKNOWN": %d},\n' \
		"${COUNT[PASS]}" "${COUNT[WARN]}" "${COUNT[FAIL]}" "${COUNT[INFO]}" "${COUNT[UNKNOWN]}"
	printf '  "findings": ['
	sep=""
	for i in "${!F_ID[@]}"; do
		[ "${F_KIND[$i]}" = L ] || continue
		printf '%s\n    %s' "$sep" "$(finding_json "$i")"
		sep=","
	done
	printf '\n  ],\n'
	if [ -z "$POLICY_FILE" ]; then
		printf '  "policy": null,\n'
	else
		printf '  "policy": {\n    "file": "%s",\n    "ssh_rules": [' "$(json_esc "$POLICY_FILE")"
		sep=""
		for i in "${!RULE_JSON[@]}"; do printf '%s\n      %s' "$sep" "${RULE_JSON[$i]}"; sep=","; done
		printf '\n    ],\n    "findings": ['
		sep=""
		for i in "${!F_ID[@]}"; do
			[ "${F_KIND[$i]}" = P ] || continue
			printf '%s\n      %s' "$sep" "$(finding_json "$i")"
			sep=","
		done
		printf '\n    ]\n  },\n'
	fi
	printf '  "todo": ['
	sep=""
	for i in "${!TODO[@]}"; do printf '%s\n    "%s"' "$sep" "$(json_esc "${TODO[$i]}")"; sep=","; done
	printf '\n  ]\n}\n'
}

progress_done
WIDTH=80
if [ -t 1 ]; then
	WIDTH=${COLUMNS:-$(tput cols 2>/dev/null || echo 81)}
	WIDTH=$((WIDTH - 1))
	[ "$WIDTH" -lt 60 ] && WIDTH=60
	[ "$WIDTH" -gt 100 ] && WIDTH=100
fi
report_txt

if [ -z "$OUT_DIR" ]; then
	OUT_DIR=$(cd "$(dirname "$0")" && pwd) || die "cannot find the script folder"
fi
mkdir -p "$OUT_DIR" 2>/dev/null || die "cannot create output dir: $OUT_DIR"
BASE="$OUT_DIR/tailscale-audit-$HOST-$DATE"
(
	C_PASS="" C_WARN="" C_FAIL="" C_INFO="" C_UNK="" C_BOLD="" C_OFF=""
	WIDTH=80
	report_txt
) >"$BASE.txt" 2>/dev/null || die "cannot write $BASE.txt (try --out DIR)"
report_json >"$BASE.json" 2>/dev/null || die "cannot write $BASE.json (try --out DIR)"
echo
echo "Report: $BASE.txt"
echo "        $BASE.json"

[ "${COUNT[FAIL]}" -gt 0 ] && exit 1
exit 0
