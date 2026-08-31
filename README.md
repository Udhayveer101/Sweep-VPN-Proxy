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

Every rung carries the *same* unmodified WireGuard tunnel — a fallback changes
the envelope, never the cryptography. `Automatic` races a diverse set (preferred
+ UDP-block survivor + web-shaped), commits only once a peer authenticates, walks
down on failure and remembers per network what worked.

Server side: `Server/sweepbridge` (Rust) terminates TCP/TLS/QUIC and relays to
wg0; rung 5 needs only a stock `ssserver`.

## Servers
`Tools/sweep-catalog` builds the catalog: your own machines, plus an optional
import of a public relay list (marked `requiresAccount`). The app measures RTT
itself and orders the list **Automatic → fastest server (pinned) → the rest,
fastest to slowest**, re-evaluated on every measurement and on network change.

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

## Not implemented (deliberately)
Rungs 2/3/5 (QUIC, REALITY/Shadowsocks-2022, WG-over-TCP) are Tier 2 in the
research roadmap. `AdapterFactory.implementedRungs` lists what actually exists;
requesting any other rung throws `rungNotImplemented` rather than silently
substituting a different transport.

## Blockers that need a human
1. **Apple Developer account.** The `packet-tunnel-provider` entitlement, an App
   Group, and provisioning profiles must be created in the developer portal, and
   `DEVELOPMENT_TEAM` set in `project.yml`. Until then the tunnel cannot run on a
   device — the simulator cannot host a NetworkExtension at all.
2. **A VPS.** Run `Server/install.sh <device-label>` on a Debian/Ubuntu host, then
   put its public key + endpoint into a bundle JSON.
3. **Signing key.** `sweep-sign keygen sweep-config.key`, then set
   `SWEEP_CONFIG_SIGNING_KEY` in `project.yml` to the printed public key. With no
   key pinned the app refuses to connect by design.
