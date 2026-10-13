Sweep VPN for Windows 10/11 (64-bit). One file, no installer, no account.

**Install:** download `SweepVPN-…-windows-x64.exe` and run it. Windows SmartScreen will say it "protected your PC" because the app is not code-signed: click **More info → Run anyway**.

**New in 2.6**
- **The Mac app's look.** The window is now the same Midnight design as Sweep on the Mac: a black canvas, one round power button whose ring shows the connection (grey off, a turning blue arc while connecting, green when connected), and a **Gaming** switch under it that picks what the button turns on: the proxy mode, or gaming mode for the whole PC. The window is dark whatever the Windows theme is, like the Mac app.
- **Updates install themselves and check that they worked.** The download is checked against the published checksum and is run once to confirm it starts and is the version it claims, before anything is replaced. The new version then has to report that it is up; if it does not, the previous version is put back and started again, and that release is not offered again by itself. After an update the window says which version you came from. Sweep can now also update when it sits on another drive than your user folder, and says so plainly when its own folder cannot be written.
- **Gaming mode** keeps private networks (10.x and 192.168.x) on your own network instead of sending them into the tunnel, so local devices and private DNS servers keep working, and is built with the Mac's current tunnel (2.1 to 2.5).
- `SweepVPN.exe -update` installs a newer version without asking, for scripts.

**First run:** the setup guide opens by itself: tick Cloudflare's terms and press **Register**. Then press the power button. The tray icon turns green when connected. Needs Microsoft Edge WebView2, which Windows 10 and 11 already have. Closing the window keeps Sweep running in the tray; turn that off in Settings ▸ This PC.

**Fixed in 1.5.1**
- Gaming mode works again: 1.5.0 was missing `wintun.dll`, so turning it on looped on "Error loading wintun.dll".

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
- **Updates itself**: it checks for a newer release once a day and offers **Update now** or **Later**, then replaces itself and restarts. Your settings and WARP registration are kept.
- Optional **Start with Windows**.

Not included: Tor mode and the VPN Connect button (Mac-only). Two things the Mac's gaming mode has are not on Windows yet: the WireGuard transport, and the quarter-second detection of a network path change (Windows reconnects when the tunnel's keepalive times out, about 8 seconds). The proxy mode only covers traffic that uses the Windows proxy — UDP (most online games, QUIC) goes direct, which is what gaming mode is for. Log: tray → **Open log**.

Verify the download: compare with the `.sha256` file (`certutil -hashfile SweepVPN-…exe SHA256`).
