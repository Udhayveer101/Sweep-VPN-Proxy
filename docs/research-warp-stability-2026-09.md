# WARP/MASQUE stability, throughput and gaming latency — research, September 2026

Primary-source research behind the September 2026 stability work. Every claim
below cites the source that owns it — RFCs, Cloudflare's own documentation,
Apple's own documentation, and the actual `usque` / `quic-go` source. Anything
that could not be traced to such a source is marked **UNVERIFIED** and is left
that way rather than filled in with something plausible.

Scope: Sweep VPN's WARP data plane — the vendored `usque` fork in `Tools/usque`,
`Kit/Sources/SweepVPNKit/WarpController.swift`, `GameModeController.swift` and
`Resources/warp/gamemode.sh`.

---

## Summary of verified findings

1. **Sweep runs MASQUE over HTTP/2, i.e. over TCP.** Both the proxy mode and
   gaming mode pass `--http2`. Cloudflare's own documentation describes MASQUE
   as an HTTP/3 connection. This is a deliberate, forced deviation: the network
   every tester is on blocks UDP.
2. **That choice structurally caps throughput and gaming latency, and no amount
   of tuning removes it.** Over HTTP/2, CONNECT-IP packets become Capsule
   Protocol DATAGRAM capsules on a single TCP stream: reliably delivered, in
   order, with nested loss recovery. Per RFC 9297 and RFC 9484 this is expected
   to reduce performance, and it means a lost game packet blocks every packet
   behind it. VERIFIED.
3. **The v1.3.0 disconnect regression was ours, not Cloudflare's.** `usque` was
   healing a dead HTTP/2 pipe in about a second in-process while the Swift
   supervisor killed and relaunched the whole child process on the same event,
   taking the SOCKS listener down with it. On a path that sweeps flows every one
   to four minutes, that produced a user-visible outage every one to four
   minutes. Fixed in `378df60`.
4. **Nothing rate-limited session churn** once a hot standby was parked, and the
   event log's own I/O turned a reconnect storm into memory pressure inside the
   extension. Both fixed in `378df60`.
5. **The Cloudflare-side numbers everyone wants do not exist publicly** — no
   first-party statement of a WARP/MASQUE idle timeout, session lifetime or
   re-registration cadence was found. UNVERIFIED.

---

## 1. MASQUE CONNECT-IP liveness and idle timeout

### What actually terminates a session

RFC 9484 ties the tunnel's life to the HTTP request stream, and defines no
keepalive of its own:

> "The lifetime of the IP forwarding tunnel is tied to the IP proxying request
> stream. The IP proxy MUST maintain all IP address and route assignments
> associated with the IP forwarding tunnel while the request stream is open."

<https://www.rfc-editor.org/rfc/rfc9484.html>

So liveness is entirely the underlying transport's problem — QUIC's idle timeout
on HTTP/3, or TCP's on HTTP/2. CONNECT-IP contributes nothing.

### QUIC (the HTTP/3 path)

RFC 9000 §10.1 negotiates the idle timeout as the **minimum of the two peers'
advertised `max_idle_timeout` values**, and recommends a liveness margin of
three times the current PTO. §10.1.2 makes PING the mechanism:

> "An endpoint SHOULD send a PING frame when it has no other frames to send but
> wishes to keep a connection alive."

<https://www.rfc-editor.org/rfc/rfc9000.html>

quic-go implements exactly that. `Config.MaxIdleTimeout` in `interface.go`:

> "MaxIdleTimeout is the maximum duration that may pass without any incoming
> network activity. The actual value for the idle timeout is the minimum of this
> value and the peer's."

with a 30 second default, and `KeepAlivePeriod`:

> "KeepAlivePeriod defines whether this peer will periodically send a packet to
> keep the connection alive. If set to 0, then no keep alive is sent."

<https://github.com/quic-go/quic-go/blob/master/interface.go>

`connection.go` clamps and paces it — note both the `idleTimeout/2` clamp and
the PTO floor, which is RFC 9000's "three times the PTO" advice in code:

```go
// c.keepAliveInterval = min(c.config.KeepAlivePeriod, c.idleTimeout/2)

func (c *Conn) nextKeepAliveTime() monotime.Time {
	if c.config.KeepAlivePeriod == 0 || c.keepAlivePingSent {
		return 0
	}
	keepAliveInterval := max(c.keepAliveInterval, c.rttStats.PTO(true)*3/2)
	return c.lastPacketReceivedTime.Add(keepAliveInterval)
}
```

```go
if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() &&
	!now.Before(keepAliveTime) {
	c.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
	c.framer.QueueControlFrame(&wire.PingFrame{})
	c.keepAlivePingSent = true
}
```

<https://github.com/quic-go/quic-go/blob/master/connection.go>

**None of this runs on our deployment.** We are on `--http2`, so there is no
QUIC connection, and `usque`'s `--keepalive-period` originally reached only the
QUIC config. That is precisely the hole `Tools/usque/masque-keepalive.patch`
fills, by wiring the same flag into `http2.Transport`:

```go
transport := &http2.Transport{
	ReadIdleTimeout: keepalive,
	PingTimeout:     h2PingTimeout,   // const h2PingTimeout = 3 * time.Second
```

Without it, per that patch's own comment, "a black-holed TCP flow is only
noticed when a write hits the kernel retransmit timeout (~20-25s), and every DNS
lookup in that window times out."

### What Cloudflare advertises or enforces

Cloudflare's first-party client documentation states the protocol choice, and
nothing about timeouts:

> "MASQUE: Establishes an HTTP/3 connection to Cloudflare. The Cloudflare One
> Client will encrypt traffic using TLS 1.3 and a FIPS 140-3 compliant cipher
> suite, `TLS_AES_256_GCM_SHA384`."

<https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/>

**UNVERIFIED:** no Cloudflare-published WARP/MASQUE idle timeout, maximum
session lifetime, or re-registration requirement was found. Do not assume one
exists; the session deaths we observe are attributable to the local path's flow
sweeping, which we have measured, not to a documented server-side limit.

### Correct client-side keepalive, restated

On HTTP/3: `KeepAlivePeriod` non-zero and below half the negotiated idle
timeout, which quic-go already enforces. On HTTP/2, which is what we ship:
`ReadIdleTimeout` plus `PingTimeout` on the transport, which is what the fork
does. Our current budget is `-k 5s` plus a 3s ping timeout, so roughly **eight
seconds of blindness** before a dead flow is noticed.

---

## 2. usque itself

Upstream: <https://github.com/Diniboy1123/usque>. We pin
`6aa03fc97d12848dce34eedbd187fb1077b5d1ea` (`Tools/usque/BASE_COMMIT`) and apply
local patches via `Tools/usque/build.sh`.

### Upstream constants and defaults

From the command flag definitions (`cmd/nativetun.go` and siblings):

| Flag | Default |
|---|---|
| `--mtu` / `-m` | `1280` |
| `--keepalive-period` / `-k` | `30 * time.Second` |
| `--initial-packet-size` / `-i` | `0` |
| `--connect-port` / `-P` | `443` |
| `--http2` | `false` |
| `--reconnect-delay` / `-r` | `1 * time.Second` |

<https://github.com/Diniboy1123/usque/blob/main/cmd/nativetun.go>

### The tunnel loop

`api/tunnel.go`, `MaintainTunnel`: buffers are allocated as
`NewNetBuffer(cfg.MTU + datagramContextIDHeadroom)` with
`const datagramContextIDHeadroom = 1` reserving room for the CONNECT-IP context
ID. Two pump goroutines run under a `sync.WaitGroup`, reporting through
`errChan := make(chan error, 2)`; device-to-network does
`cfg.Device.ReadPacket(buf[datagramContextIDHeadroom:])` then
`ipConn.WritePacketBuffer(buf, datagramContextIDHeadroom, n)`, and the reverse
pump uses `ipConn.ReadPacketZeroCopy(true)`. Session death is detected only as an
error surfacing on `errChan`; teardown allows `pumpShutdownGrace = 2 *
time.Second` before the next cycle, separated by `sleepCtx(ctx,
cfg.ReconnectDelay)`.

<https://github.com/Diniboy1123/usque/blob/main/api/tunnel.go>

Two things follow directly. **One packet per read, per write, per syscall** —
there is no batching anywhere in the loop. And **session death is inferred from
a write error**, which on a black-holed TCP flow is the kernel retransmit
timeout unless something pings.

### Our fork

Five patches, described in `Tools/usque/build.sh`, plus one added this session:

- `masque-keepalive.patch` — HTTP/2 `ReadIdleTimeout`/`PingTimeout` as above,
  plus in-tunnel DNS retry with `const dnsAttempt = 1500 * time.Millisecond`,
  because "a query sent in that gap is dropped with no retransmit."
- `masque-handshake-timeout.patch` — a 10s bound on the MASQUE dial.
- `masque-closed-pipe.patch` — ends the session when its HTTP/2 stream closes
  under a write (`isClosedPipe`), so the loop redials rather than wedging.
- `flow-standby-rotation.patch` — `--hot-standby` keeps a second session
  handshaken and idle so a kill is a promotion rather than a dial;
  `--flow-ttl` retires a healthy flow, jittered, before it is old enough to be
  swept; a retired flow lingers so the packet its device pump already read is
  carried into the next session. Its commit message records the measurement:
  "30s TTL: 11 rotations, zero kills, zero failed requests, promotion within the
  same second," and the reason aggressive detection had previously failed: "the
  `-k 2s` experiment was worse than `-k 5s` because every false positive cost a
  rebuild, and a warm standby reduces that cost to a promotion."
- `darwin-tun-framing.patch` — utun framing for the macOS `nativetun` backend.
- `standby-backoff.patch` — added this session, see §7.

### How we invoke it

`Kit/Sources/SweepVPNKit/WarpController.swift`:

```swift
["-c", configFile.path, "socks",
 "-s", sni, "--http2",
 "--always-reconnect", "-k", "5s", "--dns-timeout", "15s",
 "-d", "1.1.1.1", "-d", "1.0.0.1",
 "-b", "127.0.0.1", "-p", String(socksPort)]
```

`Resources/warp/gamemode.sh`:

```bash
ARGS=(-c "$CONFIG" nativetun -s "$SNI" --http2 --always-reconnect
      --hot-standby -k 5s -S)
```

`-S` is `--no-tunnel-ipv6`, deliberate: the script's comment records that with
IPv6 inside the tunnel "every new MASQUE session hands out a different public
address, so a rotation or reconnect changes the player's IP mid-game and the
game server drops them (measured 2026-09-18: v6 egress changed every rotation,
v4 held 104.28.217.150 across all of them)."

**UNVERIFIED:** upstream issues and commits specifically about disconnects,
throughput or keepalives were not enumerated for this document; the fork's own
patch set is the evidence used here.

---

## 3. Throughput in a Go/QUIC userspace tunnel

What the primary sources say caps throughput, and how each applies to us:

**UDP receive buffer size.** quic-go's own guidance recommends roughly 7.5 MB,
via `sysctl -w net.core.rmem_max=7500000` and `wmem_max` on Linux, and
`sysctl -w kern.ipc.maxsockbuf=8441037` on macOS.
<https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes>
**Does not apply to our shipping configuration** — `--http2` means the data path
is TCP, not a UDP socket. It becomes relevant only on the HTTP/3 path.

**Batching.** Upstream `MaintainTunnel` reads and writes one packet at a time
(§2). There is no `ReadBatch`/`WriteBatch` via `golang.org/x/net/ipv4`/`ipv6`
and no GSO/GRO. At small MTU this makes per-packet syscall and allocation cost,
not bandwidth, the limiter.

**MTU.** usque defaults to 1280, and RFC 9484 explains the floor:

> "IPv6 requires that every link have an MTU of at least 1280 bytes. Since IP
> proxying in HTTP conveys IP packets in HTTP Datagrams... the MTU of an IP
> tunnel can be limited."

<https://www.rfc-editor.org/rfc/rfc9484.html>

1280 is the safe floor, not the efficient value: on a 1500-byte path it costs
roughly 15% of every packet's payload to overhead that a larger tunnel MTU would
amortise. Sweep additionally clamps pushed settings to `(576...1500)` with a
1280 fallback (`Core/Sources/SweepVPNCore/PushedTunnelSettings.swift`).

**Nested loss recovery.** The dominant term for us, and the subject of §6.

**UNVERIFIED:** no measured throughput numbers exist for this deployment. Every
number quoted in the fork's comments is a one-off manual observation of
connectivity, not a bandwidth benchmark. Treat all throughput reasoning here as
mechanism, not measurement, until a repeatable benchmark exists.

---

## 4. Apple NetworkExtension correctness

Scope note first: **macOS gaming mode does not use NetworkExtension at all.** It
is a root shell script that creates a utun through `usque nativetun` and installs
two half-default routes:

```bash
route -n add -net 0.0.0.0/1 -interface "$IFACE"
route -n add -net 128.0.0.0/1 -interface "$IFACE"
```

`GameModeController.swift` records why: "A Developer ID app cannot install a
privileged helper without a paid Network Extension entitlement, so the admin
prompt is the honest path." This section therefore constrains the iOS/iPadOS
target and any future macOS NE build, not the shipping Mac gaming mode.

**Packet read contract.** Apple documents `readPackets(completionHandler:)` as
strictly one-shot:

> "Each call to this method results in a single execution of the completion
> handler. The caller should call this method after each `completionHandler`
> execution in order to continue to receive packets from the TUN interface."

<https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets(completionhandler:)>

The correct shape is therefore re-arm immediately at the top of every completion
handler; any path that returns early without re-arming silently stops the tunnel
in one direction, which presents to the user as a hang rather than a disconnect.

**Settings.** `NEPacketTunnelNetworkSettings` is documented as "The
configuration for a packet tunnel provider's virtual interface," carrying
`ipv4Settings`, `ipv6Settings`, `mtu`, and `tunnelOverheadBytes` — "The number of
bytes added to each tunneled packet for storing tunneling protocol headers."
<https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings>

**UNVERIFIED — the memory budget.** No Apple-published figure for a network
extension's memory limit was located. The widely repeated numbers are not
sourced here and are deliberately not quoted. What *is* verified is our own
side of it: the extension runs under a 32 MB Go memory limit and a 50 MB iOS
jetsam ceiling that we set, and §7 records a real memory-pressure bug we found
against those. The mechanism — an extension killed for memory presents as a
random disconnect — is sound reasoning, but the specific Apple threshold is not
established here.

**UNVERIFIED:** `reasserting`, `includeAllNetworks`/`enforceRoutes`, on-demand
rule behaviour across sleep/wake, Wi-Fi↔cellular handover guidance, and the
macOS-vs-iOS entitlement differences were not extracted from Apple's
documentation for this pass. They remain open questions for the iOS target.

---

## 5. Apple iCloud Private Relay

Apple's public description of the two hops:

> "Your IP address is visible to your network provider and to the first relay,
> which is operated by Apple. Your DNS records are encrypted, so neither party
> can see the address of the website you're trying to visit."

> "The second relay, which is operated by a third-party content provider,
> generates a temporary IP address, decrypts the name of the website you
> requested, and connects you to the site."

<https://support.apple.com/en-us/102602>

**UNVERIFIED:** Apple's transport internals — whether and how it uses QUIC
connection migration, preferred address, or 0-RTT to survive network transitions
— were not established from a first-party source in this pass. The December 2021
white paper could not be text-extracted here. Be honest about this: the popular
account of Private Relay's migration behaviour circulates widely but was not
verified against Apple's own words for this document.

What is nonetheless structurally clear, and worth stating with that caveat:

- **Adoptable in principle:** QUIC connection migration and 0-RTT resumption are
  properties of QUIC itself (RFC 9000), available to any MASQUE client — but only
  on an HTTP/3 path. On our HTTP/2 path a network change means a new TCP
  connection and a new TLS handshake, full stop.
- **Not adoptable:** the two-hop ingress/egress separation, which requires two
  independently operated relay fleets. We have one upstream, Cloudflare.

---

## 6. Low-latency and "gaming" requirements — and why gaming mode still drops

This is the section that explains symptoms (b) and (c), and the explanation is
structural rather than a tuning error.

CONNECT-IP carries IP packets as HTTP Datagrams (RFC 9484: "IP packets are
encoded using HTTP Datagrams with the Context ID set to zero"). How those
datagrams are actually carried depends entirely on the HTTP version. RFC 9297:

> "When running over HTTP/2, demultiplexing is provided by the HTTP/2 framing
> layer, but unreliable delivery is unavailable. HTTP Datagrams are negotiated
> and conveyed using the Capsule Protocol"

> "DATAGRAM Capsules, which are sent on a stream, are reliably delivered in
> order."

<https://www.rfc-editor.org/rfc/rfc9297.html>

And RFC 9484 names the cost directly:

> "When the protocol running inside the tunnel uses loss recovery (e.g., TCP or
> QUIC) and the outer HTTP connection runs over TCP, the proxied traffic will
> incur at least two nested loss recovery mechanisms. This can reduce
> performance."

<https://www.rfc-editor.org/rfc/rfc9484.html>

Contrast RFC 9000 §2, which is why HTTP/3 does not have this problem:

> "QUIC does not provide any means of ensuring ordering between bytes on
> different streams."

<https://www.rfc-editor.org/rfc/rfc9000.html>

Put together, on our shipping `--http2` path:

- A game's UDP packet is placed in a DATAGRAM capsule on **one TCP stream**.
  It is now **reliable and ordered**, which is the opposite of what game traffic
  wants.
- A single lost segment **head-of-line blocks every packet behind it** until TCP
  retransmits it. The game does not get a dropped packet it can ignore; it gets
  a latency spike, then a burst.
- The game's own transport and the tunnel's TCP both run loss recovery over the
  same loss event — the nested recovery RFC 9484 warns about — so congestion
  response overshoots and the queue deepens.

This is the honest answer to "gaming mode is supposed to never drop, and it
still drops": on a TCP-carried tunnel, *never dropping* and *low latency* are in
direct conflict, and the protocol chooses never-dropping. Reconnect engineering
can shorten the outages around a flow kill — and §7 does exactly that — but it
cannot remove head-of-line blocking. Only HTTP/3 removes it, and HTTP/3 needs
UDP, which this network blocks.

Secondary, and real but smaller: gaming mode is IPv4-only on purpose (§2), and
`Disguise.rotate` was measured at "zero kills over 11 rotations, but ~1 in 20 new
connections stalls in the swap window," which is why it stays opt-in.

---

## 7. What this implies for Sweep VPN

Every tester is on the same UDP-blocked, SNI-filtered network as the user.
HTTP/3 is therefore **not actionable for this deployment**, and the ranking below
reflects that: the top items are the ones that work on HTTP/2 today.

### Already found and fixed this session (commit `378df60`)

**R1. The disconnect regression was self-inflicted — fixed. VERIFIED (repo).**
`masque-closed-pipe.patch` made `usque` heal a dead HTTP/2 pipe in about one
second, in-process. `WarpController.swift` relaunched the entire `usque` child on
the same event, and v1.3.0's `case .error, .lost where …` classification made
ordinary "Tunnel connection lost" notices vote for a relaunch too. The cold
restart took the SOCKS listener down with it, so every app connection failed —
on a path that sweeps flows every one to four minutes, that was an outage every
one to four minutes. The supervisor now restarts only when `usque` has **failed**
to heal: a 15s recovery deadline, disarmed by a reconnect line, with
`StartBackoff` on repeats. This, not Cloudflare and not WARP, is symptom (a).

**R2. Session churn had no rate limit — fixed. VERIFIED (repo).**
`flow-standby-rotation.patch` skipped the reconnect delay entirely once a standby
was parked (`if len(standbyCh) > 0 { continue }`), and `fillStandby` re-dialled a
down path at 1 Hz forever. `Tools/usque/standby-backoff.patch` puts a 500 ms
floor under a promote cycle and backs standby dials off from 1s to 30s.

**R3. Gaming mode rotated twice as fast as the threat needed — fixed.
VERIFIED (repo).** `--flow-ttl` was 45s against a measured one-to-four-minute
sweep. Now 90s: still ahead of the sweep, half the churn, and half the exposure
to the ~1-in-20 swap-window stall noted in §6.

**R4. The event log fed a memory-pressure loop — fixed. VERIFIED (repo).**
`EventLog` appended synchronously on every log line and, past 4 MB, read the
whole file and rewrote 2 MB on **every** line — inside a 32 MB Go memory limit
and a 50 MB iOS jetsam ceiling. A reconnect storm therefore generated exactly the
log volume that turned it into memory pressure in the extension, which presents
as a random disconnect. Now async, tail-only, and measured at most once a minute.
(The Apple-published NE memory budget remains **UNVERIFIED**, §4; the mechanism
here is our own limits, which are known.)

### Next, on HTTP/2, ranked

**R5. Re-tune detection now that a false positive is cheap. VERIFIED as
reasoning, UNTESTED as a change.** The current `-k 5s` + 3s `PingTimeout` leaves
~8s of blindness (§1). The fork's own record says `-k 2s` lost to `-k 5s` only
because every false positive cost a rebuild; with R1 it no longer costs a
process restart. Re-run that experiment — it is now a different experiment.

Note the caveat added by measurement, and it is a large one: see
`docs/measurements-2026-09-20.md`. When a transfer stalled for 60s on the
shipping build, `usque` logged **nothing at all** — no lost session, no
reconnect. The MASQUE session stayed up while traffic through it stopped dead.
Faster *detection* cannot help with a fault the client never detects, so R5 is
not the fix for the stalls users are reporting, and should not be sold as one.

**R5a. `--hot-standby` in normal mode: tried, measured, rejected.**
The obvious companion to R5, and it did not survive a head-to-head run (both
tunnels up at once, same network, 14 minutes each): median 19.77 vs
19.34 Mbit/s, 1 failed transfer vs 0, longest unbroken 332s vs 535s. A wash on
throughput and behind on the numbers that matter. A standby is a second
long-lived TCP flow to the same endpoint on a network that sweeps long-lived TCP
flows, so an unmeasurable benefit does not pay for it. Normal mode does not pass
it; gaming mode still does, because rotation needs a warm session to rotate
into.

**R6. Raise the tunnel MTU above 1280 where the path allows. VERIFIED that 1280
is the default; the correct value is UNVERIFIED.** usque defaults to 1280 and
Sweep clamps to it (§3). On a 1500-byte path this is a standing ~15% payload tax.
Needs a PMTU probe before changing anything; do not guess.

**R7. Establish a repeatable throughput and drop benchmark. VERIFIED that none
exists.** Every number in the fork's comments is a one-off manual observation
(§3). Symptom (b) — "throughput dropped noticeably" — currently cannot be
confirmed or refuted, and R5/R6 cannot be evaluated without it. This is the
highest-value *unbuilt* thing in this list.

**R8. iOS target: re-arm `readPackets` immediately in every completion handler.
VERIFIED (Apple).** Apple's documented contract is one packet-batch per call
(§4). Audit every early-return path in the read loop.

**R9. Set expectations in the UI about gaming mode. VERIFIED (RFC 9297/9484).**
Over HTTP/2 the tunnel is reliable and ordered by construction; head-of-line
blocking under loss is not a bug we can fix on this network (§6). Better to say
so than to keep tuning toward a promise the transport cannot keep.

### Only if the network constraint ever lifts

**R10. Move to HTTP/3 (drop `--http2`).** This is the single change that removes
nested loss recovery and head-of-line blocking (RFC 9484, RFC 9297, RFC 9000 §2),
restores quic-go's native keepalive and idle-timeout negotiation in place of our
HTTP/2 PING patch (§1), and puts QUIC connection migration within reach for
network transitions (§5). It is also the configuration Cloudflare documents for
MASQUE. It is **blocked today**: every tester's network blocks UDP, so H3 would
simply fail to connect. Keep it behind a preference and re-evaluate if any tester
ever reaches a network that permits UDP/443. If that happens, R11 and R12 come
with it.

**R11. UDP socket buffers**, per quic-go's guidance —
`kern.ipc.maxsockbuf=8441037` on macOS (§3). Meaningless on TCP.

**R12. Batch the packet pumps** with `ReadBatch`/`WriteBatch` (§2/§3). Worth
doing on any path, but the payoff is on H3 where per-packet syscall cost
dominates.
