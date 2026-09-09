# Sweep VPN — iOS + macOS

A personal VPN client you run against your own server: WireGuard data plane,
kernel IKEv2 fallback, fail-closed kill switch, offline-signed control plane.

**It ships with no servers and no accounts, and that is the point.** There is no
Sweep service behind this — no endpoint of ours to trust, meter, or subpoena.
You point it at a VPS you control, or at the public VPN Gate relays with the
tradeoff spelled out below. Nothing in a build reaches for infrastructure
belonging to whoever published it.

## Getting it

**Download a build** — see [Releases](../../releases). macOS 14+, Apple silicon
and Intel. Signed and notarized, so it opens normally.

**Or build it** — `make config`, fill in `Config/Local.xcconfig`, then
`make install-macos`. Details under [Setup](#setup).

Either way, read [First run](#first-run): out of the box the app has nowhere to
connect to, and getting it somewhere is three or four steps.

## Layout
| Path | What |
|---|---|
| `Core/` | `SweepVPNCore` — state machine, Auto-mode engine, server scoring, signed-config verifier, security policy, keychain store, diagnostics, IPC. Pure Swift, host-testable. |
| `DataPlane/sweepwg/` | Rust C-ABI shim over **boringtun** (audited userspace WireGuard). No cryptography is written here. |
| `DataPlane/SweepWireGuard.xcframework` | Built static lib for ios-arm64, ios-sim (arm64+x86_64), macos (arm64+x86_64). |
| `Kit/` | `SweepVPNKit` (adapters, packet-tunnel provider, NE configurators) and `SweepVPNUI` (SwiftUI). |
| `Apps/` | iOS app + `.appex`, macOS menu-bar app + `.appex`, shared config, entitlements. |
| `Tools/sweep-sign/` | Offline Ed25519 signing CLI for the config/server bundle. |
| `Server/` | VPS provisioning: WireGuard, Unbound (in-tunnel resolver, ECS off), nftables default-deny, sshd hardening. |

## Build
```bash
make config         # once, then fill in Config/Local.xcconfig
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
make dataplane      # rebuild the xcframework from Rust
make install-macos  # build, sign, and install to /Applications
make ios            # simulator build
```

## Tests
```bash
(cd Core && swift test)            # 37 tests — policy, ladder, scoring, config, scrubbing
(cd Kit && swift test)             # 14 tests — settings mapping, presentation, loopback tunnel
(cd DataPlane/sweepwg && cargo test --release)   # real handshake + tamper/replay/PSK rejection
```

## Protocol ladder
| Rung | Transport | Beats |
|---|---|---|
| 1 | WireGuard / UDP (native port) | the normal case |
| 2 | WireGuard / UDP 443 | "block odd UDP ports" filters |
| 3 | WireGuard over QUIC datagrams :443 | UDP DPI; helps roaming |
| 4 | WireGuard over TLS 1.3, TCP :443 | networks that drop all UDP |
| 5 | Shadowsocks-2022, TCP | active probing (no plaintext handshake) |
| 6 | IKEv2 (kernel) | low power, no extension process |
| 7 | WireGuard over TCP :443 | last resort |
| 8 | OpenVPN / UDP | reaching a VPN Gate public relay |
| 9 | OpenVPN / TCP :443 | same, on UDP-blocked networks |

Rungs 1–7 carry the *same* unmodified WireGuard tunnel — a fallback changes
the envelope, never the cryptography. `Automatic` races a diverse set (preferred
+ UDP-block survivor + web-shaped), commits only once a peer authenticates, walks
down on failure and remembers per network what worked.

Rungs 8–9 are **not** part of that ladder. OpenVPN is a different protocol with
different crypto, terminating on a volunteer's machine whose key is not ours, so
`Automatic` filters them out entirely (`ProtocolRung.isOwnWireGuardTunnel`) and
they are reachable only by picking a relay by hand.

They run on **macOS only** so far. `DataPlane/sweepovpn` is a C ABI over
OpenVPN 3 — the same core OpenVPN Connect ships — and its xcframework carries
OpenSSL, lz4 and fmt statically; those still need cross-compiling for the iOS
slices. `AdapterFactory.implementedRungs` reflects that, so the rungs are not
offered where they cannot run.

Server side: `Server/sweepbridge` (Rust) terminates TCP/TLS/QUIC and relays to
wg0; rung 5 needs only a stock `ssserver`.

## Servers
`Tools/sweep-catalog` builds the catalog: your own machines, plus an optional
import of a public relay list (marked `requiresAccount`). The app measures RTT
itself and orders the list **Automatic → fastest server (pinned) → the rest,
fastest to slowest**, re-evaluated on every measurement and on network change.

## Public relays (VPN Gate)

`VPNGate.parseCSV` reads the public list at `vpngate.net/api/iphone/` — a few
hundred volunteer-run OpenVPN relays — and `PublicRelayPickerView` measures them
from this device and orders them fastest first. They are kept out of the signed
bundle on purpose: that list is vouched for by your offline key, and a
third-party CSV cannot be. See the header comment in `VPNGateFetcher` for why
they get their own cache instead.

Two things to know before relying on them:

- **The operator sees your traffic.** A relay terminates it in plaintext, and
  the `LogType` column is that operator's own unverifiable claim about what they
  keep. The picker shows it per row.
- **Roughly a third of them are dead at any moment.** They are volunteer boxes.
  A sample of ten picked at random carried real traffic on seven; the other
  three had gone away. The list is measured from the device for that reason —
  advertised speed is a guess, a probe is not.
- **macOS only.** Selecting a relay on iOS says so rather than silently failing.

How the packets move: OpenVPN 3 wants a tun file descriptor and an extension
has `packetFlow` instead, so `tun_builder_establish()` hands it one end of a
`SOCK_DGRAM` socketpair and pumps the other. OpenVPN 3 also treats that
descriptor as an Apple utun and frames every packet with a 4-byte address
family, which `packetFlow` does not use — the shim adds and strips it. The
address, resolvers and routes arrive in `PUSH_REPLY`, so they are validated
(`PushedTunnelSettings`) before they reach the network settings.

`DataPlane/sweepovpn/test/harness.c` proves the whole path outside the app: it
connects to a relay, pushes a real IPv4/UDP DNS query through the tunnel and
waits for the reply.

If your ISP blocks `vpngate.net` by category (Indian residential ISPs return a
403 block page), set a mirror URL in the picker — `Tools/worker-tunnel/deploy.sh`
puts one on your own Cloudflare account and prints what to paste. See
[If your network blocks it](#if-your-network-blocks-it).

## What ships (Tier 1)
- Rungs 1–5 and 7 in the packet tunnel (boringtun core), rung 6 as a kernel profile.
- **macOS second kill-switch layer**: `NEFilterDataProvider` that blocks by
  default whenever the tunnel is not carrying traffic.
- Kill switch: on-demand catch-all + `includeAllNetworks` + `excludeLocalNetworks`
  + provider blackhole-until-authenticated.
- DNS forced in-tunnel (`matchDomains = [""]`), IPv6 routed or blackholed, never
  left to the physical interface.
- Auto mode ladder with the researched hysteresis constants.
- Ed25519-signed, monotonic, expiring config bundle; key pinned in the app; every
  verification failure is fail-closed.
- Keychain-only secrets (AfterFirstUnlock, ThisDeviceOnly, app-group).
- Scrubbed diagnostics ring buffer (no IPs, domains or DNS names).

## Rung status
All seven rungs exist: rungs 1–5 and 7 as packet-tunnel adapters over the
boringtun core, rung 6 as a kernel IKEv2 profile.
`AdapterFactory.implementedRungs` is the source of truth — requesting anything
outside it throws `rungNotImplemented` rather than silently substituting a
different transport. Rungs 3 and 4 additionally need a TLS certificate on the
server before `sweepbridge` will serve them.

## First run

A fresh install has no servers, because there is no service to hand you any. Two
routes, and you can take both:

**Your own VPS (rungs 1–7, the real thing).** `Server/FREE-SERVERS.md` covers the
free-tier options and where each one actually falls over.

```bash
swift run --package-path Tools/sweep-sign sweep-sign keygen sweep-config.key
# paste the printed *public* key into SWEEP_CONFIG_SIGNING_KEY in Config/Local.xcconfig
./Tools/sweep-fleet.sh add home you@your-vps.example US "New York"
```

`sweep-fleet.sh` provisions the box, reads its keys back and re-signs the bundle
in one step. The private half stays in `sweep-config.key` and never leaves your
machine; the app pins the public half and refuses any server list not signed by
it, so nothing — not a compromised download host, not us — can hand it a server
you did not put there.

**Public VPN Gate relays (macOS only).** No server needed: the app fetches the
volunteer relay list and measures it from your device. Read the two warnings in
[Public relays](#public-relays-vpn-gate) before you rely on it — chiefly that the
operator terminates your traffic in plaintext.

### If your network blocks it

Some networks block `vpngate.net` by category (Indian residential ISPs return a
403), and some kill OpenVPN by protocol fingerprint the moment its handshake
hits the wire, port 443 included. Both are answered by a small Cloudflare Worker
on your own free account:

```bash
./Tools/worker-tunnel/deploy.sh
```

It prints a URL and a token. Paste them into the app under the relay list ▸
**Mirror URL…**, or into `Config/Local.xcconfig` and rebuild. The Worker mirrors
the relay CSV from a domain no category filter knows, and carries the relay's own
TCP stream inside ordinary HTTPS.

Deploy your own rather than sharing one. A Worker relaying other people's TCP is
an open proxy wearing one account's name, and that account is the one that gets
banned for whatever goes through it. No build ships one for this reason, and with
none configured the app reports the leg off rather than quietly using someone
else's.

## Setup

```bash
brew install xcodegen
make config           # creates Config/Local.xcconfig from the example
```

`Config/Local.xcconfig` is gitignored and holds everything that is yours rather
than the project's — signing team, pinned key, your own Worker. Nothing in it is
required to build; an empty value turns its feature off rather than falling back
to a stranger's server. These are deliberately absent from `project.yml`, because
a build configuration setting overrides the xcconfig beneath it and would win
silently.

You need an **Apple Developer account** to run it on hardware: the
`packet-tunnel-provider` entitlement, an App Group and provisioning profiles are
created in the developer portal, and `DEVELOPMENT_TEAM` goes in
`Config/Local.xcconfig`. NetworkExtension entitlements cannot be ad-hoc signed,
and the simulator cannot host a NetworkExtension at all.

The `.xcodeproj` is generated, not tracked — `make project` writes it from
`project.yml` plus your local config.

## What this does not collect

No account, no telemetry, no crash reporting, no analytics SDK. The diagnostics
ring buffer is scrubbed of IPs, domains and DNS names before anything reaches it
and never leaves the device. Secrets live in the keychain
(`AfterFirstUnlock`, `ThisDeviceOnly`, app-group scoped). The only network calls
a build makes on its own are to the server you configured and, if you asked for
public relays, to `vpngate.net` or the mirror you named.
