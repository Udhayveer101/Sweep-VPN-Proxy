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
MCAST_ADDED=""
DIRECT_IPS=""

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
    for ip in $DIRECT_IPS; do route -n delete -host "$ip" "$ORIG_GW" >/dev/null 2>&1; done
    [ -n "$MCAST_ADDED" ] && route -n delete -net 224.0.0.0/4 -interface "$ORIG_IF" >/dev/null 2>&1
    route -n delete -net 10.0.0.0/8 >/dev/null 2>&1
    route -n delete -net 192.168.0.0/16 >/dev/null 2>&1
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
    # The app's bootstrap runs us from a root-owned copy; remove it with us.
    case "$(dirname "$0")" in
        /private/var/run/sweep-gamemode.*) rm -rf "$(dirname "$0")" ;;
    esac
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
# The authorization trampoline gives us euid 0 but leaves the real uid at the
# user's. networksetup checks the real uid ("Command requires admin
# privileges"), so the DNS pin and its restore failed. With euid 0 we may set
# the real uid too; re-exec once as full root before touching anything.
#
# Perl turns on taint mode by itself whenever the real and effective uid differ
# (perlsec), which is exactly our case. Tainted, it refuses the inherited PATH
# and refuses to exec @ARGV, so 1.5.2's bare `exec @ARGV` died silently and
# gaming mode never started. So: PATH is set inside perl (and must carry /sbin
# for route, ifconfig and networksetup), the arguments are untainted, exec is
# list form, and any failure lands in the log. Tools/test-gamemode.sh runs
# this line under perl -T.
REEXEC_PERL='$ENV{PATH}="/usr/bin:/bin:/usr/sbin:/sbin"; delete @ENV{qw(IFS CDPATH ENV BASH_ENV)}; my @a = map { /\A(.*)\z/s; $1 } @ARGV; $< = 0; $( = 0; exec { $a[0] } @a or die "gamemode: re-exec failed: $!\n"'
if [ "$(id -ru)" -ne 0 ] && [ -z "${GAMEMODE_REEXEC:-}" ]; then
    trap - EXIT INT TERM
    export GAMEMODE_REEXEC=1
    shopt -s execfail
    log "re-exec as full root"
    exec /usr/bin/perl -e "$REEXEC_PERL" /bin/bash -p "$0" "$@" 2>>"$LOG"
    # exec only returns if perl itself could not be started.
    log "FATAL re-exec as full root failed"
    rm -f "$CONTROL"
    exit 1
fi
if [ -n "${GAMEMODE_REEXEC:-}" ] && [ "$(id -ru)" -ne 0 ]; then
    log "WARN real uid still $(id -ru); networksetup may refuse the DNS pin"
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

# Game servers the network already lets through stay off the tunnel. This
# school's Sophos gateway lets mc.hypixel.net:25565 through directly on both
# of its uplinks (IAXN and NEXTRA, measured 2026-09-27), but sweeps the
# long-lived MASQUE flow every 12-180s, and each sweep resets every game
# connection inside it. Only a host that answers a direct TCP connect *now*,
# before the tunnel takes the default route, is excluded; blocked games still
# go through WARP. Extra hosts: one per line in direct-hosts next to config.json.
DIRECT_HOSTS="mc.hypixel.net:25565"
DIRECT_FILE="$(dirname "$CONFIG")/direct-hosts"
if [ -f "$DIRECT_FILE" ] && [ ! -L "$DIRECT_FILE" ]; then
    DIRECT_HOSTS="$DIRECT_HOSTS $(grep -E '^[A-Za-z0-9.-]+(:[0-9]{1,5})?$' "$DIRECT_FILE" | head -32 | tr '\n' ' ')"
fi
for ENTRY in $DIRECT_HOSTS; do
    HOST=${ENTRY%%:*}; PORT=${ENTRY#*:}; [ "$PORT" = "$ENTRY" ] && PORT=25565
    # Both the school resolver and 1.1.1.1 (what the game will ask once DNS is
    # pinned below) - they can disagree for anycast hosts.
    IPS=$( { dscacheutil -q host -a name "$HOST" | awk '/^ip_address:/{print $2}'
             dig +short +time=2 +tries=1 A "$HOST" @1.1.1.1; } 2>/dev/null |
           grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
    for ip in $IPS; do
        if nc -z -G 3 "$ip" "$PORT" >/dev/null 2>&1; then
            route -n add -host "$ip" "$ORIG_GW" >/dev/null 2>&1 && DIRECT_IPS="$DIRECT_IPS $ip"
            log "direct: $HOST $ip:$PORT reachable, kept off the tunnel"
        else
            log "direct: $HOST $ip:$PORT not reachable, stays in the tunnel"
        fi
    done
done

# IPv4 only, deliberately: with IPv6 inside the tunnel every new MASQUE session
# hands out a different public address, so a rotation or reconnect changes the
# player's IP mid-game and the game server drops them (measured 2026-09-18:
# v6 egress changed every rotation, v4 held 104.28.217.150 across all of them).
# No --dns-timeout or -d here: nativetun moves packets and has no in-process
# resolver, unlike socks/http-proxy, and usque exits on an unknown flag. DNS is
# the system's job, which is why we point it at 1.1.1.1 below.
# Never --hot-standby or --flow-ttl. Every MASQUE session is a new connection
# at Cloudflare and does not carry the inner TCP connections across, so each
# rotation resets every open game connection. Measured 2026-09-27 through the
# shipped 1.5.0 usque: with --flow-ttl 15s/20s, 4 of 7 long TCP transfers were
# cut ("transfer closed"); without rotation 0 of 7 over the same 5.5 minutes.
# A parked standby is also swept with the live flow, so it buys nothing here
# (docs/measurements-2026-09-20.md).
# -P 8443: the firewall proxies every tcp/443 flow, see WarpController.masquePort.
ARGS=(-c "$CONFIG" nativetun -s "$SNI" --http2 -P 8443 --always-reconnect -k 5s -S)

# Start usque and wait for its utun to appear and carry our address. Only
# usque's own announcement names our device: guessing from ifconfig picked up
# whatever other VPN's utun happened to be last. The log is appended across
# runs, so only lines written after this launch count.
# Returns 0 with IFACE set, 1 if usque exited, 2 if the device never came up.
launch_usque() {
    local from
    from=$(stat -f %z "$LOG" 2>/dev/null || echo 0)
    "$USQUE" "${ARGS[@]}" >> "$LOG" 2>&1 &
    USQUE_PID=$!
    log "usque pid $USQUE_PID"
    IFACE=""
    for _ in $(seq 1 40); do
        kill -0 "$USQUE_PID" 2>/dev/null || return 1
        IFACE=$(tail -c +$((from + 1)) "$LOG" | grep -oE 'Created TUN device: utun[0-9]+' | tail -1 | awk '{print $4}')
        if [ -n "$IFACE" ] && ifconfig "$IFACE" 2>/dev/null | grep -q 'inet '; then
            return 0
        fi
        IFACE=""
        sleep 0.5
    done
    kill "$USQUE_PID" 2>/dev/null
    return 2
}

# Point both halves of the default route somewhere without a gap. Both
# commands always run: add creates the route when it is missing (and is a
# no-op when it exists), change repoints it when it exists. Never branch on
# route's exit status - macOS route(8) exits 0 when change finds no route
# ("not in table"), so 1.5.1-2.0's "change || add" never added anything and
# gaming mode ran with no tunnel routes at all (measured 2026-10-05).
point_default() {
    for HALF in 0.0.0.0/1 128.0.0.0/1; do
        route -n add -net "$HALF" "$@" >/dev/null 2>&1
        route -n change -net "$HALF" "$@" >/dev/null 2>&1
    done
}

# usque's in-process reconnect resets the utun, and macOS drops routes bound to
# it; nothing re-added them, so the Mac fell back to en0 silently (2026-09-27).
# Probe one address per half and repair whatever no longer goes via $IFACE.
# The probes are addresses nothing talks to: a host the Mac has contacted
# (1.1.1.1 is its resolver) can hold a cloned host route via the physical
# link, which would fail this check on a healthy tunnel.
routes_ok() {
    local ip
    for ip in 44.255.255.1 200.1.1.1; do
        route -n get "$ip" 2>/dev/null | grep -q "interface: $IFACE\$" || return 1
    done
}

launch_usque
case $? in
    1) log "FATAL usque exited during setup"; exit 1 ;;
    2) log "FATAL tunnel interface never came up"; exit 1 ;;
esac

TUN_ADDR=$(ifconfig "$IFACE" | awk '/inet /{print $2; exit}')
log "tunnel $IFACE addr $TUN_ADDR"

# Two halves instead of replacing the default route: they beat the existing
# default on longest-prefix match, so the original stays intact and teardown is
# a delete rather than a restore.
point_default -interface "$IFACE"
if routes_ok; then
    log "default routed through $IFACE"
else
    log "FATAL could not route through $IFACE (probe goes via $(route -n get 200.1.1.1 2>/dev/null | awk '/interface:/{print $2}'))"
    exit 1
fi

# Multicast and discovery (TTL 1) stay on the physical link. Sent into the
# tunnel they are dropped anyway ("connect-ip: datagram TTL too small: 1").
# Only delete what we added: macOS may already hold its own 224/4 route.
route -n add -net 224.0.0.0/4 -interface "$ORIG_IF" >/dev/null 2>&1 && MCAST_ADDED=1

# Private ranges stay on the physical link, as WARP's own client does. WARP
# cannot reach them, and a network whose DHCP resolvers are private (measured
# 2026-09-24: 10.1.2.10/.16 behind 192.168.3.5) otherwise loses every lookup the
# moment the DNS pin below does not take. 172.16/12 is left out: it holds the
# tunnel's own address.
for NET in 10.0.0.0/8 192.168.0.0/16; do
    route -n add -net "$NET" "$ORIG_GW" >/dev/null 2>&1
done

ORIG_SVC=$(networksetup -listnetworkserviceorder | awk -v dev="$ORIG_IF" '
    /^\([0-9]+\)/ { svc=substr($0, index($0,$2)) }
    $0 ~ "Device: "dev"\\)" { print svc; exit }')
if [ -n "$ORIG_SVC" ]; then
    ORIG_DNS=$(networksetup -getdnsservers "$ORIG_SVC" 2>/dev/null | tr '\n' ' ')
    ERR=$(networksetup -setdnsservers "$ORIG_SVC" 1.1.1.1 1.0.0.1 2>&1)
    log "dns pinned on '$ORIG_SVC' (was: $ORIG_DNS)${ERR:+ networksetup: $ERR}"
fi
# networksetup can succeed and still not change the resolver in use, so check
# what the system will actually ask.
sleep 1
log "resolvers now: $(scutil --dns | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')"

log "ready"

# Hold until the app withdraws the control file. If usque dies, restart it and
# keep the default route away from the physical link meanwhile (kill switch):
# falling back to direct mid-game is another reset, and may be blocked anyway.
# Open game connections do not survive a restart either - it is a new session -
# but the tunnel comes back without the player toggling anything.
# Five failed restarts in a row end it; a restart only counts as a success once
# usque has stayed up for a minute, so a crash loop cannot hold the Mac forever.
FAILS=0
UP_SINCE=$SECONDS
while [ -f "$CONTROL" ]; do
    if ! kill -0 "$USQUE_PID" 2>/dev/null; then
        point_default 127.0.0.1 -blackhole
        FAILS=$((FAILS + 1))
        if [ "$FAILS" -gt 5 ]; then
            log "FATAL usque would not restart; shutting down"
            exit 1
        fi
        log "usque exited; restarting (attempt $FAILS), traffic held"
        sleep $((1 << (FAILS - 1)))
        [ -f "$CONTROL" ] || break
        if launch_usque; then
            point_default -interface "$IFACE"
            log "restarted; default routed through $IFACE"
            UP_SINCE=$SECONDS
        fi
        continue
    fi
    if ! routes_ok; then
        log "split default lost (now via $(route -n get 200.1.1.1 2>/dev/null | awk '/interface:/{print $2}')); restoring"
        route -n add -host "$ENDPOINT_IP" "$ORIG_GW" >/dev/null 2>&1
        point_default -interface "$IFACE"
        routes_ok || { point_default 127.0.0.1 -blackhole; log "WARN could not restore; traffic held"; }
    fi
    [ $((SECONDS - UP_SINCE)) -ge 60 ] && FAILS=0
    sleep 1
done

log "control file withdrawn"
exit 0
