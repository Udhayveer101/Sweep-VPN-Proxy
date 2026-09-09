# Third-party components

Sweep VPN itself is Apache 2.0 (see `LICENSE`). It ships or links the following,
each under its own terms. None of them is modified: every one is used as an
unmodified upstream library behind a thin shim of ours.

| Component | Where | License | Note |
|---|---|---|---|
| [OpenVPN 3 Core](https://github.com/OpenVPN/openvpn3) | `DataPlane/openvpn/` (fetched by `fetch.sh`), linked into `SweepOpenVPN.xcframework` | AGPL-3.0-only **or** MPL-2.0, at the recipient's option | **We take the MPL-2.0 option.** MPL is file-level copyleft, so the upstream files stay MPL and our shim (`DataPlane/sweepovpn/`) does not become copyleft. Upstream grants an explicit additional permission to link against OpenSSL. |
| [boringtun](https://github.com/cloudflare/boringtun) | `DataPlane/sweepwg/` | BSD-3-Clause | Cloudflare's audited userspace WireGuard. The WireGuard cryptography is theirs; none is reimplemented here. |
| [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) | `DataPlane/sweepwg/` | MIT | Rung 5 (Shadowsocks-2022). |
| [OpenSSL](https://openssl-library.org/) | statically inside `SweepOpenVPN.xcframework` | Apache-2.0 | TLS for the OpenVPN rungs. |
| [lz4](https://github.com/lz4/lz4), [fmt](https://github.com/fmtlib/fmt) | statically inside `SweepOpenVPN.xcframework` | BSD-2-Clause, MIT | Pulled in by OpenVPN 3. |
| [Tor](https://www.torproject.org/) | bundled by `Tools/bundle-tor.sh` when present | BSD-3-Clause | Optional; not built by default. |

`Core/Tests/SweepVPNCoreTests/Fixtures/vpngate-sample.csv` is a captured sample
of the public [VPN Gate](https://www.vpngate.net/) relay list, published by its
operators for exactly this use. The private keys inside it are the ones VPN Gate
publishes to the world with each relay — they are not credentials of ours, and
they are not secret to anyone.

## MPL-2.0 source availability

MPL-2.0 requires that the source of the covered files be available to anyone who
receives a binary. `DataPlane/openvpn/fetch.sh` pins the exact upstream commit
this project builds against, so a release binary can always be traced back to
the source it came from:

    git clone https://github.com/OpenVPN/openvpn3.git
    git checkout 7f572f4fe647a36f5a1094cbeb261a5bcdae5047
