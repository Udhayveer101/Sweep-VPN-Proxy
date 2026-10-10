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
# The loop must come back from its wait even with SIGALRM blocked, which is how
# the authorization trampoline starts us. A `read -t` wait hangs there forever.
perl -MPOSIX -e 'sigprocmask(SIG_BLOCK, POSIX::SigSet->new(SIGALRM)); exec @ARGV' /bin/bash -c '
    LOG="$1/alrm.log"; CONTROL="$1/alrm.control"; : > "$LOG"; : > "$CONTROL"
    USQUE_PID=$$ IFACE=utun9 ENDPOINT_IP=192.0.2.1 ORIG_GW=192.0.2.254
    log() { :; }; routes_ok() { :; }
    ( /bin/sleep 2; rm -f "$CONTROL" ) &
    . "$1/loop.sh"' _ "$TMP" &
LOOP=$!
( sleep 8; kill -9 "$LOOP" 2>/dev/null ) & GUARD=$!
if wait "$LOOP" 2>/dev/null; then { kill "$GUARD"; wait "$GUARD"; } 2>/dev/null || true
else echo "FAIL: hold loop did not stop within 8s of the control file going away (SIGALRM blocked)" >&2; exit 1; fi
# Wi-Fi off and on takes the endpoint pins with it and may bring another
# gateway. The repair must pin every address again, through the gateway that is
# there now.
REPAIR=$(
    set +e
    LOG="$TMP/pin.log"; CONTROL="$TMP/pin.control"; : > "$LOG"; : > "$CONTROL"
    USQUE_PID=1 IFACE=utun9 ENDPOINT_IP=192.0.2.1 ORIG_GW=192.0.2.254 WG_IP=192.0.2.2 DIRECT_IPS=" 192.0.2.3"
    LOST=1
    kill() { return 0; }
    log() { :; }; point_default() { :; }
    routes_ok() { [ "$LOST" -eq 0 ] && return 0; LOST=0; return 1; }
    netstat() { echo "default            198.51.100.1       UGScg                 en0"; }
    # The script silences route, so the stub keeps its own record.
    route() { [ "$2" = add ] && echo "pin:$4:$5" >> "$TMP/pins"; return 0; }
    sleep() { N=$((${N:-0} + 1)); [ "$N" -ge 2 ] && rm -f "$CONTROL"; return 0; }
    . "$TMP/loop.sh" >/dev/null
    cat "$TMP/pins" 2>/dev/null
)
WANT=$'pin:192.0.2.1:198.51.100.1\npin:192.0.2.2:198.51.100.1\npin:192.0.2.3:198.51.100.1'
[ "$REPAIR" = "$WANT" ] || {
    echo "FAIL: after the pins were lost, expected all three re-pinned via the new gateway, got:"; echo "$REPAIR"; exit 1; } >&2
# When the WireGuard engine exits mid-session, the next start must be MASQUE,
# under the kill switch: restarting an engine that just died risks a restart
# loop that ends gaming mode and puts the Mac back on the open network.
RESTART=$(
    set +e
    LOG="$TMP/wg.log"; CONTROL="$TMP/wg.control"; : > "$LOG"; : > "$CONTROL"
    USQUE_PID=1 IFACE=utun9 ENDPOINT_IP=192.0.2.1 ORIG_GW=192.0.2.254 WG_IP=192.0.2.2
    MODE=wireguard ARGS=(wgtun) MASQUE_ARGS=(nativetun)
    DEAD=1
    kill() { [ "$DEAD" -eq 0 ]; }
    log() { :; }; routes_ok() { :; }; route() { :; }; point_default() { echo "default:$*"; }
    launch_usque() { DEAD=0; echo "launch:${ARGS[*]}:$MODE"; }
    sleep() { N=$((${N:-0} + 1)); [ "$N" -ge 3 ] && rm -f "$CONTROL"; return 0; }
    . "$TMP/loop.sh"
)
WANT=$'default:127.0.0.1 -blackhole\nlaunch:nativetun:masque\ndefault:-interface utun9'
[ "$RESTART" = "$WANT" ] || {
    echo "FAIL: after the WireGuard engine exits, expected a held MASQUE restart, got:"; echo "$RESTART"; exit 1; } >&2
echo "gamemode.sh checks passed"
