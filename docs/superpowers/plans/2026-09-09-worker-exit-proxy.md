# Worker-as-Exit SOCKS Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Cloudflare Worker the exit node itself, so browsing reaches the internet through `wss://<worker>.workers.dev` with no VPN Gate relay, no packet tunnel, and no relay churn.

**Architecture:** `LocalProxy` already speaks SOCKS5 + HTTP-CONNECT on loopback and already has a pluggable `Upstream` enum. Add a third case, `.worker`, whose dial opens a `MinimalWebSocket` to the Worker's `/tcp` endpoint and splices it to the client socket. On the Worker, the destination allow-list widens from "VPN Gate relays only" to "anything that passes a safety guard", still behind `TUNNEL_TOKEN`. Nothing in `ConnectionCoordinator`, `OpenVPNTunnelAdapter`, or the relay pool is touched — the VPN path keeps working exactly as it does today, and this ships beside it.

**Tech Stack:** Swift 5.9 / Network.framework (`NWConnection`, `NWListener`), Cloudflare Workers + Durable Objects (`cloudflare:sockets`), XcodeGen, `wrangler`, XCTest, `node --test`.

## Global Constraints

- Branch: `vpn-overhaul`. No git remote — commits stay local (`project_sweep_vpn`).
- macOS only. `LocalProxy.swift` is inside `#if os(macOS)`; every new file follows that guard.
- Never hand-edit `SweepVPN.xcodeproj`. Regenerate with `make project` (XcodeGen from `project.yml`).
- Never set `GENERATE_INFOPLIST_FILE: YES` or a target `info:` block — both silently drop `NSExtension`.
- The proxy binds `127.0.0.1` only. A proxy reachable from the LAN is an open relay.
- The Worker must never log destination host, port, or per-chunk sizes. That is the metadata a VPN exists not to produce.
- `/tcp` stays gated on `TUNNEL_TOKEN`, compared in constant time.
- Secrets live in `Config/Local.xcconfig` (gitignored). Never commit a token.
- `make install-macos` is the only trustworthy install. Never test a `CODE_SIGNING_REQUIRED=NO` build (`sweep_vpn_macos_signing`).
- After editing any struct in `Core`, `rm -rf Kit/.build` before `swift test` — SPM does not rebuild `Kit` and a stale binary segfaults in `swift_release`.

## File Structure

| File | Responsibility |
|---|---|
| `Tools/worker-tunnel/worker.js` (modify) | Widen `/tcp` destination policy; add `isSafeDestination` guard |
| `Tools/worker-tunnel/worker.test.mjs` (modify) | Cover the new guard |
| `Kit/Sources/SweepVPNKit/WorkerStream.swift` (create) | One TCP-over-WSS stream to the Worker; `NWConnection`-shaped façade |
| `Kit/Sources/SweepVPNKit/LocalProxy.swift` (modify) | Add `.worker` upstream case + dial path |
| `Kit/Sources/SweepVPNUI/VPNViewModel.swift` (modify) | Return `.worker` from `currentUpstream()` when enabled |
| `Kit/Sources/SweepVPNUI/SettingsView.swift` (modify) | Toggle for "Route proxy through Worker" |
| `Kit/Tests/SweepVPNKitTests/WorkerStreamTests.swift` (create) | Stream framing + status-byte handling |
| `Kit/Tests/SweepVPNKitTests/LocalProxyTests.swift` (modify) | End-to-end SOCKS → fake Worker |

---

### Task 1: Widen the Worker's destination policy behind a safety guard

**Files:**
- Modify: `Tools/worker-tunnel/worker.js` (the `isAllowed` call site in `export default.fetch`, ~line 390)
- Test: `Tools/worker-tunnel/worker.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `isSafeDestination(host: string, port: number) -> boolean`, exported for test. `/tcp` accepts any host passing it, in addition to the existing relay list.

This is the security-critical task. Widening the allow-list turns a relay-only tunnel into a general proxy; the token is the gate, and the guard below is what stops it being usable for the two things that get a Cloudflare account banned — spam relaying, and reaching into private address space.

- [ ] **Step 1: Write the failing test**

Append to `Tools/worker-tunnel/worker.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { isSafeDestination } from "./worker.js";

test("isSafeDestination allows ordinary public web destinations", () => {
  assert.equal(isSafeDestination("example.com", 443), true);
  assert.equal(isSafeDestination("example.com", 80), true);
  assert.equal(isSafeDestination("1.1.1.1", 443), true);
});

test("isSafeDestination refuses private and loopback address space", () => {
  for (const h of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                   "169.254.169.254", "0.0.0.0", "localhost", "[::1]", "::1"]) {
    assert.equal(isSafeDestination(h, 443), false, h);
  }
});

test("isSafeDestination refuses mail ports, so this cannot relay spam", () => {
  for (const p of [25, 465, 587, 2525]) {
    assert.equal(isSafeDestination("example.com", p), false, String(p));
  }
});

test("isSafeDestination refuses a nonsense port", () => {
  assert.equal(isSafeDestination("example.com", 0), false);
  assert.equal(isSafeDestination("example.com", 70000), false);
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/sweep-vpn/Tools/worker-tunnel && node --test
```

Expected: FAIL — `SyntaxError: The requested module './worker.js' does not provide an export named 'isSafeDestination'`

- [ ] **Step 3: Write minimal implementation**

Add to `Tools/worker-tunnel/worker.js`, just above `tokenMatches`:

```js
/// Ports that make this Worker useful to a spammer rather than to its owner.
/// Cloudflare blocks outbound 25 itself, but 465/587/2525 are the submission
/// ports an abuse report would name, and the account carrying the blame is
/// the one that deployed this.
const REFUSED_PORTS = new Set([25, 465, 587, 2525]);

/// Address space that is private to whoever runs the far end. Reaching it
/// through someone else's proxy is SSRF, not browsing — 169.254.169.254 in
/// particular is the cloud metadata endpoint.
function isPrivateAddress(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal")) return true;
  if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, Number(m[2]), Number(m[3]), Number(m[4])].some((n) => n > 255)) return true;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;              // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;    // CGNAT
  if (a >= 224) return true;                            // multicast + reserved
  return false;
}

/// The destination policy for the general-exit mode. The token is the gate;
/// this is what keeps a leaked token from being worth much.
export function isSafeDestination(host, port) {
  if (!host) return false;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (REFUSED_PORTS.has(port)) return false;
  return !isPrivateAddress(host);
}
```

Then change the destination check inside `export default.fetch`, replacing:

```js
      if (!(await isAllowed(host))) return refused("not a known relay");
```

with:

```js
      // Two ways to be an acceptable destination. A VPN Gate relay, as before —
      // that path is what the OpenVPN rungs use and its behaviour is unchanged.
      // Or any ordinary public host, which is the general-exit mode: the Worker
      // stops being a way to reach a relay and becomes the exit itself, which
      // is the whole point of dropping the relay pool.
      if (!isSafeDestination(host, port) && !(await isAllowed(host))) {
        return refused("destination refused");
      }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd ~/sweep-vpn/Tools/worker-tunnel && node --test
```

Expected: PASS, all tests including the pre-existing ones.

- [ ] **Step 5: Commit**

```bash
cd ~/sweep-vpn && git add Tools/worker-tunnel/worker.js Tools/worker-tunnel/worker.test.mjs
git commit -m "Let the Worker be the exit, not just the way to one

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: `WorkerStream` — one TCP-over-WSS connection to the Worker

**Files:**
- Create: `Kit/Sources/SweepVPNKit/WorkerStream.swift`
- Test: `Kit/Tests/SweepVPNKitTests/WorkerStreamTests.swift`

**Interfaces:**
- Consumes: `MinimalWebSocket` (`init(connection:host:path:)`, `handshake(completion:)`, `send(_:)`, `receive(onMessage:onClose:)`), and `RelayTunnelSettings` (`workerURL: URL`, `token: String`, `load(appGroup:)`).
- Produces:
  - `final class WorkerStream` with
    `static func open(settings: RelayTunnelSettings, host: String, port: Int, queue: DispatchQueue, completion: @escaping (WorkerStream?) -> Void)`
  - `func send(_ data: Data)`
  - `func receive(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void)`
  - `func cancel()`

`WebSocketTransport` is not reused here on purpose: it stands up a whole `NWListener` per instance and carries relay-session resume logic. A browser opens dozens of connections, so a listener each is the wrong shape. This is the same wire protocol without the session machinery.

- [ ] **Step 1: Write the failing test**

Create `Kit/Tests/SweepVPNKitTests/WorkerStreamTests.swift`:

```swift
#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

final class WorkerStreamTests: XCTestCase {

    /// The path must carry the destination and the token, or the Worker
    /// answers `forbidden` and the failure looks like a dead network.
    func testPathCarriesDestinationAndToken() {
        let path = WorkerStream.path(host: "example.com", port: 443, token: "abc123")
        XCTAssertTrue(path.hasPrefix("/tcp?"))
        XCTAssertTrue(path.contains("h=example.com"))
        XCTAssertTrue(path.contains("p=443"))
        XCTAssertTrue(path.contains("t=abc123"))
        XCTAssertTrue(path.contains("s="), "a session id is required by the DO router")
    }

    /// A host with characters that are legal in a hostname but not in a query
    /// must not be able to smuggle a second parameter.
    func testPathEscapesTheDestination() {
        let path = WorkerStream.path(host: "evil.com&p=25", port: 443, token: "t")
        XCTAssertFalse(path.contains("evil.com&p=25"))
        XCTAssertTrue(path.contains("evil.com%26p%3D25"))
    }

    /// Every stream gets its own session, or two connections would collide in
    /// the same Durable Object and interleave their bytes.
    func testEachPathGetsAFreshSession() {
        let a = WorkerStream.path(host: "example.com", port: 443, token: "t")
        let b = WorkerStream.path(host: "example.com", port: 443, token: "t")
        XCTAssertNotEqual(a, b)
    }
}
#endif
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/sweep-vpn/Kit && swift test --filter WorkerStreamTests
```

Expected: FAIL — `cannot find 'WorkerStream' in scope`

- [ ] **Step 3: Write minimal implementation**

Create `Kit/Sources/SweepVPNKit/WorkerStream.swift`:

```swift
#if os(macOS)
import Foundation
import Network

/// One TCP connection, carried to its destination inside a WebSocket to the
/// Worker.
///
/// This is the general-exit mode: the Worker dials the destination itself, so
/// there is no VPN Gate relay in the path and none of what comes with one —
/// no pool, no `AUTH_FAILED`, no 62-second idle FIN, no handover. It also means
/// no packet tunnel, so no NetworkExtension entitlement and no kill switch.
///
/// The channel is the one that is measured to work on this network: ordinary
/// TLS on :443 to an uncategorised `workers.dev` host, which the Sophos gateway
/// cannot look inside because TLS inspection is off.
///
/// Deliberately *not* `WebSocketTransport`: that stands up an `NWListener` per
/// instance and carries relay-session resume. A browser opens dozens of
/// connections at once and a listener each is the wrong shape. Same wire
/// protocol, none of the session machinery.
public final class WorkerStream: @unchecked Sendable {

    private let socket: MinimalWebSocket
    private let connection: NWConnection
    private let closed = NSLock()
    private var isClosed = false

    private init(socket: MinimalWebSocket, connection: NWConnection) {
        self.socket = socket
        self.connection = connection
    }

    /// The destination travels in the query, so it must be escaped. An
    /// unescaped `&` in a hostname would otherwise let the caller append a
    /// parameter of its own — a different port, for one.
    static func path(host: String, port: Int, token: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func esc(_ s: String) -> String {
            s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
        }
        // A fresh session per stream. The id keys the Durable Object, so two
        // streams sharing one would interleave their bytes into a single
        // socket. No resume: these are short and a redial is cheaper than
        // parking bytes for one.
        let session = UUID().uuidString
        return "/tcp?h=\(esc(host))&p=\(port)&t=\(esc(token))&s=\(esc(session))"
    }

    /// Dials the Worker, upgrades, and waits for the one-byte status the Worker
    /// sends once it has reached the destination: 0x01 connected, 0x00 failed.
    /// Calls back with nil on any failure along the way.
    public static func open(settings: RelayTunnelSettings,
                            host: String,
                            port: Int,
                            queue: DispatchQueue,
                            completion: @escaping @Sendable (WorkerStream?) -> Void) {
        guard let workerHost = settings.workerURL.host else { return completion(nil) }
        let workerPort = NWEndpoint.Port(rawValue: UInt16(settings.workerURL.port ?? 443)) ?? 443

        let params = NWParameters.tls
        let conn = NWConnection(host: NWEndpoint.Host(workerHost), port: workerPort, using: params)

        let done = OneShot(completion)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ws = MinimalWebSocket(
                    connection: conn,
                    host: workerHost,
                    path: path(host: host, port: port, token: settings.token))
                ws.handshake { error in
                    if error != nil { conn.cancel(); return done.fire(nil) }
                    // The status byte can share a segment with the 101, which is
                    // why MinimalWebSocket keeps the tail of that read.
                    ws.receive(onMessage: { data in
                        guard let first = data.first else { return }
                        guard first == 0x01 else { conn.cancel(); return done.fire(nil) }
                        done.fire(WorkerStream(socket: ws, connection: conn))
                    }, onClose: { _ in
                        conn.cancel()
                        done.fire(nil)
                    })
                }
            case .failed, .cancelled:
                done.fire(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    public func send(_ data: Data) {
        guard !data.isEmpty else { return }
        socket.send(data)
    }

    /// Bytes from the destination. The status byte has already been consumed by
    /// `open`, so everything delivered here is payload.
    public func receive(onData: @escaping @Sendable (Data) -> Void,
                        onClose: @escaping @Sendable () -> Void) {
        socket.receive(onMessage: { data in
            if !data.isEmpty { onData(data) }
        }, onClose: { [weak self] _ in
            self?.markClosed()
            onClose()
        })
    }

    public func cancel() {
        markClosed()
        connection.cancel()
    }

    private func markClosed() {
        closed.lock()
        defer { closed.unlock() }
        isClosed = true
    }

    /// `stateUpdateHandler` fires repeatedly and can reach `.failed` after
    /// `.ready`; resuming a dial twice would hand one stream to two splices.
    /// Same reason `LocalProxy.DialOnce` exists.
    private final class OneShot: @unchecked Sendable {
        private var fired = false
        private let lock = NSLock()
        private let body: @Sendable (WorkerStream?) -> Void
        init(_ body: @escaping @Sendable (WorkerStream?) -> Void) { self.body = body }
        func fire(_ s: WorkerStream?) {
            lock.lock()
            if fired { lock.unlock(); return }
            fired = true
            lock.unlock()
            body(s)
        }
    }
}
#endif
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd ~/sweep-vpn/Kit && swift test --filter WorkerStreamTests
```

Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/sweep-vpn && git add Kit/Sources/SweepVPNKit/WorkerStream.swift Kit/Tests/SweepVPNKitTests/WorkerStreamTests.swift
git commit -m "Carry one TCP connection to the Worker without a listener

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Give `LocalProxy` a `.worker` upstream

**Files:**
- Modify: `Kit/Sources/SweepVPNKit/LocalProxy.swift` — `Upstream` enum (~line 17), `connectUpstream` (~line 243), `splice`/`pump` (~line 334)
- Test: `Kit/Tests/SweepVPNKitTests/LocalProxyTests.swift`

**Interfaces:**
- Consumes: `WorkerStream.open(settings:host:port:queue:completion:)`, `send(_:)`, `receive(onData:onClose:)`, `cancel()` from Task 2.
- Produces: `LocalProxy.Upstream.worker(RelayTunnelSettings)`. `LocalProxy(port:upstream:)` unchanged.

The existing `splice(_:_:)` takes two `NWConnection`s. A `WorkerStream` is not one, so this adds a second splice for the mixed pair rather than making the existing one generic — one extra function beats a protocol with two conformers.

- [ ] **Step 1: Write the failing test**

Append to `Kit/Tests/SweepVPNKitTests/LocalProxyTests.swift`, inside `final class LocalProxyTests`:

```swift
    /// `.worker` must be a real, distinct upstream — not silently equal to
    /// `.direct`, which would send traffic straight at the blocked network and
    /// look like the proxy working.
    func testWorkerUpstreamIsDistinct() throws {
        let settings = RelayTunnelSettings(
            enabled: true,
            workerURL: try XCTUnwrap(URL(string: "https://example.workers.dev")),
            token: "t")
        let worker = LocalProxy.Upstream.worker(settings)
        XCTAssertNotEqual(worker, LocalProxy.Upstream.direct)
        XCTAssertNotEqual(worker, LocalProxy.Upstream.socks5(host: "127.0.0.1", port: 9050))
    }

    /// A proxy configured for the Worker must still be constructible and bind
    /// loopback, or the Settings toggle would fail with no state to show.
    func testProxyStartsWithWorkerUpstream() throws {
        let settings = RelayTunnelSettings(
            enabled: true,
            workerURL: try XCTUnwrap(URL(string: "https://example.workers.dev")),
            token: "t")
        let proxy = try XCTUnwrap(LocalProxy(port: 18081, upstream: .worker(settings)))
        let listening = expectation(description: "listening")
        proxy.start(upstream: .worker(settings)) { state in
            if case .listening = state { listening.fulfill() }
        }
        wait(for: [listening], timeout: 5)
        proxy.stop()
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/sweep-vpn/Kit && swift test --filter LocalProxyTests
```

Expected: FAIL — `type 'LocalProxy.Upstream' has no member 'worker'`

- [ ] **Step 3: Write minimal implementation**

In `Kit/Sources/SweepVPNKit/LocalProxy.swift`, add the case to `Upstream`:

```swift
        /// Chain through another SOCKS5 proxy, i.e. Tor.
        case socks5(host: String, port: Int)
        /// Carry each connection to the Cloudflare Worker, which dials the
        /// destination itself. No relay, no packet tunnel — the Worker is the
        /// exit. This is the mode that works on a network where App Control
        /// kills a bare OpenVPN handshake but TLS to workers.dev passes.
        case worker(RelayTunnelSettings)
```

Replace `connectUpstream` entirely:

```swift
    private func connectUpstream(host: String, port: Int,
                                 done: @escaping (NWConnection?) -> Void) {
        switch upstream {
        case .direct:
            dial(host: host, port: port) { done($0) }
        case .socks5(let proxyHost, let proxyPort):
            dial(host: proxyHost, port: proxyPort) { [weak self] conn in
                guard let self, let conn else { return done(nil) }
                self.socksClientHandshake(conn, host: host, port: port) { ok in
                    if ok { done(conn) } else { conn.cancel(); done(nil) }
                }
            }
        case .worker:
            // Handled in `accept`'s completion path, which has the client
            // connection to splice against. Nothing to return here.
            done(nil)
        }
    }

    /// The Worker path needs both ends at once — a `WorkerStream` is not an
    /// `NWConnection`, so it cannot be returned through `connectUpstream`.
    private func connectWorker(_ client: NWConnection,
                               settings: RelayTunnelSettings,
                               host: String, port: Int,
                               done: @escaping (Bool) -> Void) {
        WorkerStream.open(settings: settings, host: host, port: port, queue: queue) { stream in
            guard let stream else { return done(false) }
            self.splice(client, stream)
            done(true)
        }
    }

    /// Client <-> Worker. The mixed-type twin of `splice(_:_:)`.
    private func splice(_ client: NWConnection, _ stream: WorkerStream) {
        stream.receive(onData: { data in
            client.send(content: data, completion: .contentProcessed { _ in })
        }, onClose: {
            client.cancel()
        })
        pumpToWorker(client, stream)
    }

    private func pumpToWorker(_ client: NWConnection, _ stream: WorkerStream) {
        client.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) { data, _, done, error in
            if let data, !data.isEmpty { stream.send(data) }
            if done || error != nil {
                stream.cancel(); client.cancel(); return
            }
            self.pumpToWorker(client, stream)
        }
    }
```

Now route the two request handlers through it. In `socksRequest`, at the point where it currently calls `connectUpstream(host:port:done:)`, replace that call with:

```swift
        if case .worker(let settings) = upstream {
            connectWorker(client, settings: settings, host: host, port: port) { ok in
                guard ok else { return self.socksFail(client, code: 0x05) }
                // SOCKS5 success, bound address 0.0.0.0:0 — the real bound
                // address is the Worker's and is not ours to disclose.
                let reply = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                client.send(content: reply, completion: .contentProcessed { _ in })
            }
            return
        }
```

And in `httpConnect`, at its `connectUpstream` call site:

```swift
        if case .worker(let settings) = upstream {
            connectWorker(client, settings: settings, host: host, port: port) { ok in
                guard ok else { return self.httpFail(client, "502 Bad Gateway") }
                client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
                            completion: .contentProcessed { _ in })
            }
            return
        }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd ~/sweep-vpn/Kit && swift test --filter LocalProxyTests
```

Expected: PASS, including the pre-existing `.direct` tests.

- [ ] **Step 5: Run the whole Kit suite for regressions**

```bash
cd ~/sweep-vpn && rm -rf Kit/.build && make test
```

Expected: PASS. Baseline is 103 tests (`sweep_vpn_openvpn_self_reconnect`); expect 108 now.

- [ ] **Step 6: Commit**

```bash
cd ~/sweep-vpn && git add Kit/Sources/SweepVPNKit/LocalProxy.swift Kit/Tests/SweepVPNKitTests/LocalProxyTests.swift
git commit -m "Point the loopback proxy at the Worker instead of the network

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Surface the mode in the app

**Files:**
- Modify: `Kit/Sources/SweepVPNUI/VPNViewModel.swift:184-189` (`currentUpstream`)
- Modify: `Kit/Sources/SweepVPNUI/SettingsView.swift:82` (proxy toggle block)

**Interfaces:**
- Consumes: `LocalProxy.Upstream.worker(_:)` from Task 3.
- Produces: `VPNOptions.proxyThroughWorker: Bool`, default `false`.

- [ ] **Step 1: Add the option**

Find the `VPNOptions` struct (it carries `localProxyEnabled` and `localProxyPort`) and add beside them:

```swift
    /// Send proxied connections to the Worker rather than straight out. On a
    /// filtered network "straight out" is the thing that does not work.
    public var proxyThroughWorker: Bool = false
```

- [ ] **Step 2: Teach `currentUpstream` about it**

Replace `currentUpstream()` in `VPNViewModel.swift`:

```swift
    private func currentUpstream() -> LocalProxy.Upstream {
        if options.torEnabled, torState == .running, let port = tor?.socksPort {
            return .socks5(host: "127.0.0.1", port: port)
        }
        if options.proxyThroughWorker {
            let settings = RelayTunnelSettings.load(appGroup: AppGroup.identifier)
            if settings.enabled, !settings.token.isEmpty {
                return .worker(settings)
            }
        }
        return .direct
    }
```

Note: `AppGroup.identifier` is whatever constant the file already uses for `RelayTunnelSettings.load` elsewhere — grep for `load(appGroup:` and match it exactly rather than inventing a name.

- [ ] **Step 3: Add the toggle**

In `SettingsView.swift`, directly after the existing local-proxy `Toggle` (line ~82):

```swift
                    Toggle("Route proxy through Worker", isOn: Binding(
                        get: { model.options.proxyThroughWorker },
                        set: { model.setProxyThroughWorker($0) }))
                        .disabled(!model.options.localProxyEnabled)
                    Text("Each connection travels inside HTTPS to your Cloudflare Worker, which dials the site for you. No VPN profile needed.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
```

And the setter in `VPNViewModel.swift`, beside `setLocalProxy`:

```swift
    public func setProxyThroughWorker(_ on: Bool) {
        var o = options
        o.proxyThroughWorker = on
        apply(options: o)
        syncProxyUpstream()
    }
```

- [ ] **Step 4: Build and run the suite**

```bash
cd ~/sweep-vpn && rm -rf Kit/.build && make test
```

Expected: PASS. `MacUISnapshotTests` may need its recorded snapshot refreshed — if it fails on a layout diff only, re-record it; if it fails on anything else, stop.

- [ ] **Step 5: Commit**

```bash
cd ~/sweep-vpn && git add Kit/Sources/SweepVPNUI/
git commit -m "Offer the Worker exit as a setting

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Deploy the Worker and prove the exit works end to end

**Files:**
- No source changes. This task is verification.

**Interfaces:**
- Consumes: Task 1's deployed Worker, Task 3's proxy.

This also clears the outstanding deploy debt: `maxParkedBytes` 512 KB → 4 MB (commit 962a768) is committed but was never deployed (`sweep_vpn_throughput`).

- [ ] **Step 1: Deploy**

```bash
cd ~/sweep-vpn/Tools/worker-tunnel && npx --yes wrangler deploy
```

Expected: `Uploaded sweep-relay-mirror` and a `https://sweep-relay-mirror.<subdomain>.workers.dev` URL.

- [ ] **Step 2: Confirm the token secret is still set**

```bash
cd ~/sweep-vpn/Tools/worker-tunnel && npx --yes wrangler secret list
```

Expected: a row named `TUNNEL_TOKEN`. If absent, re-run `./deploy.sh`, which mints a fresh one and prints where to paste it.

- [ ] **Step 3: Prove the Worker reaches an arbitrary host**

Read the token out of the gitignored config, then ask the Worker for a real site:

```bash
cd ~/sweep-vpn && TOKEN=$(sed -n 's/^[[:space:]]*SWEEP_TUNNEL_TOKEN[[:space:]]*=[[:space:]]*//p' Config/Local.xcconfig) && node -e '
const WebSocket = require("ws");
const url = process.env.URL + "/tcp?h=example.com&p=80&t=" + process.env.TOKEN + "&s=" + Date.now();
const ws = new WebSocket(url);
ws.binaryType = "arraybuffer";
let first = true;
ws.on("open", () => {});
ws.on("message", (d) => {
  const b = Buffer.from(d);
  if (first) {
    first = false;
    console.log("status", b[0] === 1 ? "CONNECTED" : "FAILED");
    if (b[0] !== 1) process.exit(1);
    ws.send(Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"));
    return;
  }
  console.log(b.toString("utf8").split("\r\n")[0]);
  process.exit(0);
});
ws.on("error", (e) => { console.log("ERROR", e.message); process.exit(1); });
setTimeout(() => { console.log("TIMEOUT"); process.exit(1); }, 15000);
' URL="https://sweep-relay-mirror.$(npx --yes wrangler whoami 2>/dev/null | sed -n 's/.*\([a-z0-9-]*\)\.workers\.dev.*/\1/p' | head -1).workers.dev" TOKEN="$TOKEN"
```

Expected: `status CONNECTED` then `HTTP/1.1 200 OK`. This is the whole thesis in one command — if it prints 200, the Worker is an exit node.

- [ ] **Step 4: Confirm the safety guard refuses private space**

Re-run Step 3 with `h=169.254.169.254&p=80`.

Expected: `status FAILED` and a `1008 destination refused` close. If it connects, stop and fix Task 1 — the Worker is an SSRF hole.

- [ ] **Step 5: Commit nothing, note the deploy**

No code changed. Record the deployed state in the commit log of the next task instead.

---

### Task 6: Build, install, and verify the live app on this Mac

**Files:**
- No source changes. This is the "make sure the latest version is live on my Mac" half of the request.

Two things have historically gone wrong here and both look like app bugs: an ad-hoc-signed build fails at connect time with "permission denied", and an app installed outside `/Applications` is rejected before it reaches the daemon (`sweep_vpn_macos_signing`).

- [ ] **Step 1: Confirm the config file has your Worker in it**

```bash
cd ~/sweep-vpn && grep -E 'SWEEP_TUNNEL_URL|SWEEP_TUNNEL_TOKEN|DEVELOPMENT_TEAM' Config/Local.xcconfig
```

Expected: three non-empty values, team `P66SB4MX92`. If `Config/Local.xcconfig` does not exist, `make config` then fill it from `deploy.sh`'s output.

- [ ] **Step 2: Regenerate the project and install**

```bash
cd ~/sweep-vpn && make install-macos
```

Expected: ends with `installing .../SweepVPN.app -> /Applications` and a `codesign -dv` block naming your Apple Development identity. Any line mentioning `CODE_SIGNING_REQUIRED=NO` means the wrong target ran — stop.

- [ ] **Step 3: Verify the installed bundle is the build you just made**

```bash
ls -lT /Applications/SweepVPN.app/Contents/MacOS/ && git -C ~/sweep-vpn log -1 --format='HEAD %h %ad' --date=iso
```

Expected: the binary's timestamp is *after* the HEAD commit time. A binary older than HEAD is the exact trap from 2026-09-08, where the installed app predated the fix by 21 seconds and the fix appeared not to work.

- [ ] **Step 4: Verify the seal survived Tor bundling**

```bash
codesign --verify --deep --strict /Applications/SweepVPN.app && echo SEAL-OK
```

Expected: `SEAL-OK`. "a sealed resource is missing or invalid" means something was copied into `Contents/Resources` after signing.

- [ ] **Step 5: Turn the mode on and prove it end to end**

Launch `/Applications/SweepVPN.app`, then in Settings enable **Local proxy** and **Route proxy through Worker**. Then, with the VPN *disconnected*:

```bash
curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w '%{http_code} %{remote_ip}\n' https://api.ipify.org
curl -s -o /dev/null -w 'direct: %{http_code}\n' --max-time 8 https://api.ipify.org
```

Expected: the first prints `200` and an IP. Use `socks5h`, not `socks5` — the `h` keeps hostname resolution at the Worker, which matters because system DNS is unreliable here and resolving locally would leak the destination to the ISP's resolver anyway.

- [ ] **Step 6: Prove it is actually the Worker's egress, not yours**

```bash
echo "direct:"; curl -s --max-time 8 https://api.ipify.org; echo
echo "proxied:"; curl -s -x socks5h://127.0.0.1:1080 https://api.ipify.org; echo
```

Expected: two different addresses, the proxied one belonging to Cloudflare. Identical addresses mean `currentUpstream()` fell through to `.direct` — check that `RelayTunnelSettings.load` found a non-empty token.

- [ ] **Step 7: Prove it beats the block**

Point the proxy at something the gateway actually blocks:

```bash
curl -s -o /dev/null -w 'blocked-direct: %{http_code}\n' --max-time 8 https://www.vpngate.net/
curl -s -o /dev/null -w 'via-worker:     %{http_code}\n' -x socks5h://127.0.0.1:1080 --max-time 15 https://www.vpngate.net/
```

Expected: direct gives 403 (the Sophos block page); via-worker gives 200. That is the measurement that says the whole thing works.

- [ ] **Step 8: Commit the plan and record the state**

```bash
cd ~/sweep-vpn && git add docs/superpowers/plans/2026-09-09-worker-exit-proxy.md
git commit -m "Plan and verify the Worker-as-exit proxy

Worker deployed with the widened destination policy and the 4 MB parked
buffer that commit 962a768 added but never shipped. Verified on this Mac:
vpngate.net is 403 direct and 200 through the proxy.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## What this plan deliberately does not do

- **Does not remove the relay pool.** `ConnectionCoordinator`, `RelayThroughputStore`, standby warming and the OpenVPN rungs all stay. They become redundant for browsing, but deleting them is a separate change that should happen only once this mode has run for a while. Ship beside, then delete.
- **Does not carry UDP.** Cloudflare's `connect()` is TCP only. Games on UDP transport still need the VPN path, or idea 2 (Codespaces).
- **Does not set the system-wide proxy.** Per-app configuration (browser, or `curl -x`) is enough to prove and use it, and writing `networksetup -setsocksfirewallproxy` needs admin rights for a change the user may not want system-wide.
- **Does not multiplex.** One WebSocket per TCP connection is simple and correct. If the free plan's 100k requests/day turns out to bind, multiplexing several streams over one socket is the fix — measure first.
