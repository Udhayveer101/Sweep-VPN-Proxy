Sweep VPN for Windows 10/11 (64-bit). One file, no installer, no account.

**Install:** download `SweepVPN-…-windows-x64.exe` and run it. Windows SmartScreen will say it "protected your PC" because the app is not code-signed: click **More info → Run anyway**. The app lives in the tray (the ^ next to the clock).

**First run:** right-click the tray icon → **Set up WARP…** → accept Cloudflare's terms. Then tick **Route this PC through WARP**. The icon turns green when connected.

- Cloudflare WARP over MASQUE with a disguised SNI (HTTP/2) — the same patched tunnel as the Mac app.
- Routes Windows through WARP via the system proxy (Edge, Chrome, Firefox on default settings, most apps). No admin rights.
- Single apps can instead use the HTTP proxy at `127.0.0.1:1080`.
- Reconnects on its own: dead-tunnel detection, restart on crash, retries while you want to be connected.
- Fail-closed: while WARP reconnects, traffic waits instead of leaking outside it.
- Quitting, a crash, or a shutdown puts your own proxy settings back.
- **Gaming mode**: routes the whole PC at the packet level through the same tunnel, so games and the UDP they send go through WARP instead of straight out to your ISP. Needs administrator rights (Windows will ask). Turning it on takes the proxy mode down, and quitting puts your routes back.
- **Updates itself**: it checks for a newer release once a day and offers **Update now** or **Later**. The download is checked against the published checksum before it replaces the app.
- Optional **Start with Windows**.

Not included: Tor mode and the VPN Connect button (Mac-only). The proxy mode only covers traffic that uses the Windows proxy — UDP (most online games, QUIC) goes direct, which is what gaming mode is for. Log: tray → **Open log**.

Verify the download: compare with the `.sha256` file (`certutil -hashfile SweepVPN-…exe SHA256`).
