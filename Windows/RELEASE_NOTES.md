Sweep VPN for Windows 10/11 (64-bit). One file, no installer, no account.

**Install:** download `SweepVPN-…-windows-x64.exe` and run it. Windows SmartScreen will say it "protected your PC" because the app is not code-signed: click **More info → Run anyway**.

**New in 1.5: a real app window**, the same screens as the Mac app — the status card with one big Route button, Settings (WARP setup, gaming mode, proxy, SNI, start with Windows, updates), the step-by-step WARP setup guide and the connection log. Closing the window keeps Sweep running in the tray (click the icon to reopen it); turn that off in Settings ▸ This PC to make closing quit, like the Mac. Needs Microsoft Edge WebView2, which Windows 10 and 11 already have.

**First run:** the setup guide opens by itself: tick Cloudflare's terms and press **Register**. Then press **Route this PC through WARP**. The tray icon turns green when connected.

**Fixed in 1.5**
- The tunnel is no longer restarted while WARP is already reconnecting by itself, or because one website failed to load (the same fix the Mac got in 1.4.1). This was the main cause of short drop-outs.
- Gaming mode re-applies its routes when the tunnel reconnects, retries after a failure, works on non-English Windows, and turning it off then using the proxy mode now works in the same session.
- Updating or relaunching no longer shows "already running" and exits; launching Sweep again brings its window forward.
- The log rolls over at 5 MB instead of growing forever.

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
