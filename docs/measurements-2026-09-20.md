# Tunnel measurements, 20 September 2026

Recorded with `Tools/soak.sh` against the real WARP tunnel on the filtered
network, so the numbers below can be argued with instead of remembered wrongly.
Re-run it before changing any of the flags these justify.

## Method

`Tools/soak.sh <minutes> <socks host:port>` pulls a 10MB file from
`proof.ovh.net` through the SOCKS port every 5s and records curl's own
`speed_download` and `time_total`. It is deliberately not a Cloudflare host:
measuring WARP through Cloudflare measures the thing inside itself.

Two harness faults were found and fixed while doing this, both of which had
already produced a wrong answer:

- Timing came from `date +%s`, so a 10MB transfer could only be 3s or 4s and
  nothing between. Two runs differing by well under a second read as
  "27.96 Mbit/s vs 20.97 Mbit/s" — an artefact that looks exactly like a
  regression. Now taken from curl.
- The first target (`speed.hetzner.de`) is unreachable through this tunnel, so
  the first run measured nothing but failures.

## Baseline: the shipping build

15 minutes, `usque` from `/Applications/Sweep VPN.app`, the flags v1.4.0 ships:

```
transfers:        82 ok, 4 failed (each a 60s stall mid-transfer)
median:           see note below — this run predates the timing fix
longest unbroken: 145s
```

The **145s** is the number that matters and does not depend on the timing bug:
the longest the tunnel went without a failed transfer was about two and a half
minutes, which matches the ISP sweeping long-lived TCP flows every 1-4 minutes.

Note on the stalls: when one happened, `usque` logged **nothing**. No lost
session, no reconnect, no standby promotion. The MASQUE session stayed up while
a transfer through it stalled to a halt and timed out at 60s. So these are not
session kills the client can see and recover from — which is exactly why the
client-side recovery changes below cannot be credited with fixing them.

## Head to head: `--hot-standby` in normal mode

Both tunnels running **at the same time** on different ports, so they saw the
same network and the same drift. 14 minutes each.

| | A: `--hot-standby` | B: shipping flags |
|---|---|---|
| transfers | 67 ok, 1 failed | 62 ok, 0 failed |
| median | 19.77 Mbit/s | 19.34 Mbit/s |
| mean | 18.10 Mbit/s | 16.93 Mbit/s |
| p10 | 7.60 Mbit/s | 6.06 Mbit/s |
| longest unbroken | 332s | 535s |

(Absolute figures are roughly halved by the two tunnels contending for one
uplink. The comparison is what this run is for.)

**Verdict: a wash.** Slightly ahead on throughput percentiles, behind on the two
numbers that actually matter — failed transfers and longest unbroken stretch.
One run each is not enough to call it either way, and "not enough to call" is
not a reason to ship it: a standby is a second long-lived TCP flow to the same
endpoint, on the network that sweeps long-lived TCP flows. So normal mode does
**not** pass `--hot-standby`. Gaming mode still does, because rotation needs a
warm session to rotate into.

## Rejected: `l4-socks`

`usque` prints a startup hint recommending `l4-socks` for TCP-only SOCKS use,
which is exactly what normal mode is. Its help text: *"TCP-only SOCKS5 proxy
using direct HTTP/3 CONNECT streams."* HTTP/3 is QUIC is UDP, and this network
blocks UDP. Not available here.

## What is still unmeasured

- Whether raising the MTU off 1280 helps. `--mtu` exists on `socks` mode; no
  run has compared values.
- Whether gaming mode's flow rotation actually removes the stalls above. It is
  the one mechanism that would, since it retires a flow *before* it reaches the
  stalled state, and the stalls are invisible to every reactive mechanism.
  Worth testing with `--hot-standby --flow-ttl 90s` on a normal-mode port.
- Anything on iOS/iPadOS. Every number here is macOS.

## Head to head: gaming mode's flow rotation

Both tunnels up at once again, 18 minutes each. A ran the gaming-mode recipe
(`--hot-standby --flow-ttl 90s`), B the shipping flags. 16 rotations happened.

| | A: rotate (90s TTL) | B: no rotation |
|---|---|---|
| transfers | 86 ok, 1 failed | 87 ok, 0 failed |
| median | 23.05 Mbit/s | 22.89 Mbit/s |
| mean | 22.32 Mbit/s | 23.40 Mbit/s |
| **p10** | **1.76 Mbit/s** | **19.95 Mbit/s** |
| longest unbroken | 611s | 654s |

Rotation itself works exactly as designed — retire, promote, new standby warm,
all inside about two seconds, 16 times with no lost session. The problem is what
it costs. **The tenth-percentile transfer collapses from 19.95 Mbit/s to
1.76 Mbit/s.** The median is untouched, which is precisely why this was never
noticed: on average nothing is wrong, and every so often everything is.

That is the "~1 in 20 new connections stalls in the swap window" the original
rotation commit admitted, measured. For bulk transfer it averages out. For a
game it does not average out — a periodic collapse to 1.76 Mbit/s *is* an
interruption, which is the one thing gaming mode promises not to have.

Note also that B suffered **zero** stalls across the whole 18 minutes. Rotation
spent a real, repeated cost defending against something that did not happen in
this window.

**Conclusion: rotation should stay off by default**, which it already is —
`gameDisguise` defaults to `.standby`. It is the wrong default to reach for when
someone reports that gaming mode stutters, and the UI should stop implying
otherwise. Raising the TTL from 45s to 90s halves how often the cost is paid,
which is worth keeping, but it does not remove it.

## The standby is swept with the live flow

The `--hot-standby` verdict above was "a wash", with no explanation for why a
warm, already-handshaken session did not help. This run explains it. `usque`
now stamps each session at dial time and prints the age in two lines —
`Promoted standby MASQUE session (age N s)` and `Tunnel connection lost after
N s` — so a promotion can be judged instead of guessed at
(`Tools/usque/standby-age-log.patch`).

28 minutes, `--hot-standby` on, `Tools/soak.sh` driving it, port 1091:

```
live-session lifetimes:  n=26  min 8.0s  median 34.0s  max 254.1s
promotions:              26
promoted already dead:   11   ages 15.5 21.8 27.9 31.3 31.9 34.0 45.7 49.7 58.2 109.4 210.8
promoted and held:       15   ages 0.1 0.3 0.4 0.6 1.0 1.0 1.4 1.8 1.9 2.7 3.0 7.8 8.3 17.9 209.2
```

"Already dead" means a `Tunnel connection lost` line inside 2s of the
promotion — usually the *same second*. The pattern is not really about age: it
is whether the standby existed across the sweep. A standby parked before the
kill is torn down by the same kill, whatever age it has reached, and its death
is only noticed once it is promoted and written to. Fourteen of the fifteen
sessions that held were dialled *after* the kill (0.1-8.3s old).

So **42% of recoveries promoted a corpse**, and each one cost a wasted promote
cycle — about 2s — ahead of the dial that actually worked. Two of them back to
back is what the iOS journal of 2026-09-20 shows:

```
10:20:59 lost ... 10:20:59 Promoted standby ... 10:20:59 connected ... 10:20:59 lost
10:21:00 Standby warm ... 10:21:00 Promoted standby ... 10:21:00 connected
```

No parking policy fixes this. An age bound was written and then thrown away
against this data: deaths at 15.5s and 21.8s leave no window to park in. A
standby is only worth keeping where the promotion is *planned* — flow rotation —
and it is worthless as kill recovery. iOS passed `HotStandby: true` in every
mode and now passes it only with rotation on, which is what macOS
(`WarpController` vs `gamemode.sh`) and Windows already did.

Note also the sweep is harsher than the "every 1-4 minutes" the code comments
still say: median session life here was **34 seconds**, shortest 8.

## A per-connection failure is not a wedge

From the macOS journal, same day:

```
10:08:19 SOCKS TCP handle from 127.0.0.1:63517 failed: dial: lookup ...: no such host
10:08:19 watching: no reconnect within 15s is a wedge
10:08:34 restarting: no reconnect within 15s after: ... no such host (waiting 2s)
10:08:37 starting: sni=... port=1081
```

One SOCKS client asked for a name that does not resolve. The MASQUE session was
healthy and was never lost — so no `Connected to MASQUE server` line could ever
follow to stand the deadline down, and 15s later the supervisor restarted a
working tunnel and took the SOCKS listener with it. `WarpController.classify`
armed the wedge deadline on any line containing "failed" or "error", and every
per-connection failure has that shape: nothing reconnects, because nothing was
disconnected. It now arms only on the four session-level lines usque actually
prints (`sessionFaultPhrases`), and logs everything else as `clientLog`.

This is the v1.3.0 regression a second time — an expensive recovery fired by an
event that did not need it — reached by a different route.

### Paired A/B, standby on vs off

Both tunnels up at once on the same instrumented binary, ports 1091 and 1092,
over a 625s overlap window:

| | A: `--hot-standby` | B: no standby |
|---|---|---|
| transfers | 40 | 41 |
| median | 23.05 Mbit/s | 23.17 Mbit/s |
| mean | 21.27 Mbit/s | 22.30 Mbit/s |
| transfers stalled ≥20s | 6 | 5 |

Throughput is a wash again, and one extra stall over ten minutes is not a result
worth leaning on — n is far too small. The finding that decides this is the
promotion tally above, which is mechanical rather than statistical: 11 of 26
promotions handed the tunnel a session the network had already killed. One
directly observed instance, for the record: at 17:07:19 A took a full 60s stall
while B transferred through the same window at 29, 23, 20 and 28 Mbit/s.
