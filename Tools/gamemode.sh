#!/bin/bash
# Gaming mode: route the whole Mac through WARP's MASQUE tunnel, UDP included.
#
# The proxy mode the app ships only catches apps that honour a SOCKS proxy.
# Games do not: they send gameplay over UDP, which this ISP drops outright, so
# they either bypass the VPN or stall. A real TUN device catches every packet,
# and MASQUE CONNECT-IP carries UDP inside one ordinary HTTPS flow.
#
# Runs as root (utun and the routing table need it). Everything it changes is
# undone by cleanup() on any exit path, including a kill, so a crash cannot
# leave the Mac routing into a dead tunnel.
#
# Control: the app creates $CONTROL before launching and deletes it to stop us.
# The app is not root and cannot signal a root process, so this is the handshake.

set -uo pipefail

USQUE="${1:?usque path required}"
CONFIG="${2:?config.json path required}"
CONTROL="${3:?control file path required}"
LOG="${4:?log path required}"
SNI="${5:-example.com}"
ROTATE="${6:-0}"        # flow-ttl; "0" disables rotation

# usque --http2 dials endpoint_h2_v4 from the registration, or this default
# (config/endpoints.go). Pinning a different address than the one it dials
# would route the tunnel's own packets into the tunnel.
ENDPOINT_IP=$(/usr/bin/plutil -extract endpoint_h2_v4 raw -o - "$CONFIG" 2>/dev/null)
[[ "$ENDPOINT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ENDPOINT_IP="162.159.198.2"
IFACE=""
ORIG_GW=""
ORIG_SVC=""
ORIG_DNS=""
USQUE_PID=""

# We run as root and the log sits in the user's Library: never follow a link
# someone swapped in, or root would append to whatever it points at.
if [ -L "$LOG" ] || [ -L "$CONTROL" ]; then
    exit 1
fi

log() { echo "$(date '+%H:%M:%S') gamemode: $*" >> "$LOG"; }

cleanup() {
    log "restoring network"
    [ -n "$USQUE_PID" ] && kill "$USQUE_PID" 2>/dev/null
    # Routes first: leaving the split default in place while the tunnel dies
    # would black-hole the Mac.
    route -n delete -net 0.0.0.0/1 >/dev/null 2>&1
    route -n delete -net 128.0.0.0/1 >/dev/null 2>&1
    [ -n "$ORIG_GW" ] && route -n delete -host "$ENDPOINT_IP" "$ORIG_GW" >/dev/null 2>&1
    if [ -n "$ORIG_SVC" ]; then
        # networksetup's "none set" answer is a sentence, not an address list.
        if [ -z "${ORIG_DNS// /}" ] || [[ "$ORIG_DNS" == *"aren't any DNS Servers"* ]]; then
            networksetup -setdnsservers "$ORIG_SVC" "Empty" >/dev/null 2>&1
        else
            # shellcheck disable=SC2086
            networksetup -setdnsservers "$ORIG_SVC" $ORIG_DNS >/dev/null 2>&1
        fi
    fi
    rm -f "$CONTROL"
    log "stopped"
}
trap cleanup EXIT INT TERM

log "starting"

# Without root every route change silently no-ops and usque cannot make a utun,
# which used to surface as "usque exited during setup" and sent people to the
# WARP settings for a privilege problem.
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log "FATAL not running as root"
    exit 1
fi

ORIG_GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
ORIG_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
if [ -z "$ORIG_GW" ]; then
    log "FATAL no default gateway; refusing to start"
    exit 1
fi
log "gateway $ORIG_GW via $ORIG_IF"

# The MASQUE endpoint must stay reachable over the physical link, or the
# tunnel's own packets would route into the tunnel.
route -n add -host "$ENDPOINT_IP" "$ORIG_GW" >/dev/null 2>&1
log "pinned $ENDPOINT_IP via $ORIG_GW"

# IPv4 only, deliberately: with IPv6 inside the tunnel every new MASQUE session
# hands out a different public address, so a rotation or reconnect changes the
# player's IP mid-game and the game server drops them (measured 2026-09-18:
# v6 egress changed every rotation, v4 held 104.28.217.150 across all of them).
# No --dns-timeout or -d here: nativetun moves packets and has no in-process
# resolver, unlike socks/http-proxy, and usque exits on an unknown flag. DNS is
# the system's job, which is why we point it at 1.1.1.1 below.
# --hot-standby only with rotation. A parked standby is swept in the same sweep
# as the live flow whatever age it has reached, so as kill recovery it delivers a
# corpse and costs ~2s before the dial that works (measured 2026-09-20: 11 of 26
# promotions were already dead — docs/measurements-2026-09-20.md). Rotation is
# the one case that needs it, because there the promotion is planned.
ARGS=(-c "$CONFIG" nativetun -s "$SNI" --http2 --always-reconnect -k 5s -S)
if [ "$ROTATE" != "0" ]; then
    ARGS+=(--hot-standby --flow-ttl "$ROTATE")
    log "flow rotation every $ROTATE"
fi

"$USQUE" "${ARGS[@]}" >> "$LOG" 2>&1 &
USQUE_PID=$!
log "usque pid $USQUE_PID"

# Wait for the utun to appear and carry our address.
for _ in $(seq 1 40); do
    kill -0 "$USQUE_PID" 2>/dev/null || { log "FATAL usque exited during setup"; exit 1; }
    # Only usque's own announcement names our device. Guessing from ifconfig
    # picked up whatever other VPN's utun happened to be last (Tailscale, the
    # Sweep packet tunnel) and routed the whole Mac into it.
    IFACE=$(grep -oE 'Created TUN device: utun[0-9]+' "$LOG" | tail -1 | awk '{print $4}')
    if [ -n "$IFACE" ] && ifconfig "$IFACE" 2>/dev/null | grep -q 'inet '; then
        break
    fi
    IFACE=""
    sleep 0.5
done

if [ -z "$IFACE" ]; then
    log "FATAL tunnel interface never came up"
    exit 1
fi

TUN_ADDR=$(ifconfig "$IFACE" | awk '/inet /{print $2; exit}')
log "tunnel $IFACE addr $TUN_ADDR"

# Two halves instead of replacing the default route: they beat the existing
# default on longest-prefix match, so the original stays intact and teardown is
# a delete rather than a restore.
route -n add -net 0.0.0.0/1 -interface "$IFACE" >/dev/null 2>&1
route -n add -net 128.0.0.0/1 -interface "$IFACE" >/dev/null 2>&1
log "default routed through $IFACE"

ORIG_SVC=$(networksetup -listnetworkserviceorder | awk -v dev="$ORIG_IF" '
    /^\([0-9]+\)/ { svc=substr($0, index($0,$2)) }
    $0 ~ "Device: "dev"\\)" { print svc; exit }')
if [ -n "$ORIG_SVC" ]; then
    ORIG_DNS=$(networksetup -getdnsservers "$ORIG_SVC" 2>/dev/null | tr '\n' ' ')
    networksetup -setdnsservers "$ORIG_SVC" 1.1.1.1 1.0.0.1 >/dev/null 2>&1
    log "dns pinned on '$ORIG_SVC' (was: $ORIG_DNS)"
fi

log "ready"

# Hold until the app withdraws the control file, or usque dies.
while [ -f "$CONTROL" ]; do
    if ! kill -0 "$USQUE_PID" 2>/dev/null; then
        log "usque exited; shutting down"
        exit 1
    fi
    sleep 1
done

log "control file withdrawn"
exit 0
