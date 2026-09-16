Sweep VPN for Windows 10/11 (64-bit). One file, no installer, no account.

**Install:** download `SweepVPN-…-windows-x64.exe` and run it. Windows SmartScreen will say it "protected your PC" because the app is not code-signed: click **More info → Run anyway**. The app lives in the tray (the ^ next to the clock).

**First run:** right-click the tray icon → **Set up WARP…** → accept Cloudflare's terms. Then tick **Route this PC through WARP**. The icon turns green when connected.

- Cloudflare WARP over MASQUE with a disguised SNI (HTTP/2) — the same patched tunnel as the Mac app.
- Routes Windows through WARP via the system proxy (Edge, Chrome, Firefox on default settings, most apps). No admin rights.
- Single apps can instead use the HTTP proxy at `127.0.0.1:1080`.
- Reconnects on its own: dead-tunnel detection, restart on crash, retries while you want to be connected.
- Fail-closed: while WARP reconnects, traffic waits instead of leaking outside it.
- Quitting, a crash, or a shutdown puts your own proxy settings back.
- Optional **Start with Windows**.

Not included: Tor mode and the VPN Connect button (Mac-only). Like the Mac's system-wide switch, it only covers traffic that uses the Windows proxy — UDP (most online games, QUIC) goes direct. Log: tray → **Open log**.

Verify the download: compare with the `.sha256` file (`certutil -hashfile SweepVPN-…exe SHA256`).
