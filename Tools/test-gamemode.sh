#!/bin/bash
# Checks for Tools/gamemode.sh that need no root: syntax, and the perl re-exec
# line run under perl -T. Taint mode is what perl switches on by itself when
# the real and effective uid differ, which is how the authorization trampoline
# launches us; 1.5.2 shipped a line that died there without a word.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT=Tools/gamemode.sh

bash -n "$SCRIPT"

# Pull the exact program the script execs, so the test cannot drift from it.
PROG=$(sed -n "s/^REEXEC_PERL='\(.*\)'\$/\1/p" "$SCRIPT")
[ -n "$PROG" ] || { echo "FAIL: REEXEC_PERL not found in $SCRIPT" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/child.sh" <<'CHILD'
for a in "$@"; do printf '%s\n' "$a"; done
for t in route ifconfig networksetup; do printf 'which %s=%s\n' "$t" "$(command -v "$t")"; done
CHILD

# A hostile inherited PATH must not matter: perl sets its own.
OUT=$(PATH="/nonexistent:$PATH" IFS=$' \t\n' /usr/bin/perl -T -e "$PROG" \
    /bin/bash -p "$TMP/child.sh" "/Users/x/Library/Application Support/a b" "plain" 2>&1) || {
    echo "FAIL: re-exec exited $?: $OUT" >&2; exit 1; }

expect() { grep -qxF "$1" <<<"$OUT" || { echo "FAIL: missing '$1' in:"; echo "$OUT"; exit 1; } >&2; }
expect "/Users/x/Library/Application Support/a b"
expect "plain"
expect "which route=/sbin/route"
expect "which ifconfig=/sbin/ifconfig"
expect "which networksetup=/usr/sbin/networksetup"

# The pre-1.5.2 line must fail here, or this test proves nothing.
if /usr/bin/perl -T -e '$< = $<; exec @ARGV or die' /bin/echo ok >/dev/null 2>&1; then
    echo "FAIL: old line passed under -T; taint is not being exercised" >&2; exit 1
fi

# The hold loop, run for 30 passes with the root-only commands stubbed. It must
# check routes for 5 passes at the start and after a new log line, on every
# 10th pass, and not otherwise: checking every second cost more CPU than usque.
sed -n '/^# --- hold loop/,/^# --- end hold loop/p' "$SCRIPT" > "$TMP/loop.sh"
[ -s "$TMP/loop.sh" ] || { echo "FAIL: hold loop markers not found in $SCRIPT" >&2; exit 1; }
CHECKS=$(
    set +e
    LOG="$TMP/hold.log"; CONTROL="$TMP/hold.control"
    echo "earlier run" > "$LOG"; : > "$CONTROL"
    USQUE_PID=1 IFACE=utun9 ENDPOINT_IP=192.0.2.1 ORIG_GW=192.0.2.254
    N=0 SEEN=""
    kill() { return 0; }
    log() { :; }
    routes_ok() { SEEN="$SEEN $N"; }
    sleep() {
        N=$((N + 1))
        [ "$N" -eq 12 ] && echo "Tunnel connection lost" >> "$LOG"
        [ "$N" -ge 30 ] && rm -f "$CONTROL"
        return 0
    }
    . "$TMP/loop.sh"
    echo "$SEEN"
)
WANT=" 0 1 2 3 4 9 12 13 14 15 16 19 29"
[ "$CHECKS" = "$WANT" ] || {
    echo "FAIL: route checks ran on passes '$CHECKS', expected '$WANT'" >&2; exit 1; }
echo "gamemode.sh checks passed"
