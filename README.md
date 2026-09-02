# Sweep VPN — iOS + macOS

Implementation of the architecture researched in the VPN Obsidian vault
(`~/VPN`). Security-first personal VPN: WireGuard data plane, kernel IKEv2
fallback, fail-closed kill switch, offline-signed control plane, frosted-glass
client.

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
brew install xcodegen
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
make dataplane      # rebuild the xcframework from Rust
xcodegen generate
xcodebuild -project SweepVPN.xcodeproj -scheme SweepVPN-iOS -sdk iphonesimulator build
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
403 block page), set a mirror URL in the picker. A Cloudflare Worker that
fetches the CSV and returns it is about fifteen lines and is reachable from a
domain no category filter knows.

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

## Blockers that need a human
1. **Apple Developer account.** The `packet-tunnel-provider` entitlement, an App
   Group, and provisioning profiles must be created in the developer portal, and
   `DEVELOPMENT_TEAM` set in `project.yml`. Until then the tunnel cannot run on a
   device — the simulator cannot host a NetworkExtension at all.
2. **A VPS.** `./Tools/sweep-fleet.sh add <label> <user@host> <CC> [city]`
   provisions the box, reads its keys back and re-signs the bundle in one step.
   See `Server/FREE-SERVERS.md` for the free-tier options and their real limits.
3. **Signing key.** `sweep-sign keygen sweep-config.key`, then set
   `SWEEP_CONFIG_SIGNING_KEY` in `project.yml` to the printed public key. With no
   key pinned the app refuses to connect by design.
