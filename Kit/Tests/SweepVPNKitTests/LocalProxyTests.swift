#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

/// Drives the proxy with a real TCP client over loopback. The SOCKS5 and
/// HTTP-CONNECT paths are byte protocols; a wrong length prefix or a missed
/// reply field fails silently at runtime, so they are exercised for real.
final class LocalProxyTests: XCTestCase {

    /// Trivial origin server: accepts, echoes back a fixed banner.
    private func startEchoServer() throws -> (NWListener, UInt16) {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        let listener = try NWListener(using: params, on: .any)
        listener.newConnectionHandler = { conn in
            conn.start(queue: .global())
            conn.receive(minimumIncompleteLength: 1, maximumLength: 1024) { _, _, _, _ in
                conn.send(content: Data("PONG".utf8), completion: .contentProcessed { _ in })
            }
        }
        let ready = expectation(description: "listener ready")
        listener.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        listener.start(queue: .global())
        wait(for: [ready], timeout: 5)
        return (listener, listener.port!.rawValue)
    }

    private func startProxy(port: Int) throws -> LocalProxy {
        let proxy = try XCTUnwrap(LocalProxy(port: port, upstream: .direct))
        let up = expectation(description: "proxy listening")
        proxy.start { state in if case .listening = state { up.fulfill() } }
        wait(for: [up], timeout: 5)
        return proxy
    }

    /// Sends `payload`, then reads until `expected.count` bytes arrive.
    private func exchange(port: UInt16, send: [Data], expecting: Int,
                          timeout: TimeInterval = 10) throws -> Data {
        let conn = NWConnection(host: "127.0.0.1", port: .init(rawValue: port)!, using: .tcp)
        let done = expectation(description: "exchange")
        let state = ExchangeState(pending: send, expecting: expecting, conn: conn) { done.fulfill() }
        conn.stateUpdateHandler = { if case .ready = $0 { state.begin() } }
        conn.start(queue: .global())
        wait(for: [done], timeout: timeout)
        conn.cancel()
        return state.received
    }

    /// The Network callbacks are @Sendable, so the read/write loop lives in a
    /// locked box rather than in recursive local functions.
    private final class ExchangeState: @unchecked Sendable {
        private let lock = NSLock()
        private var pending: [Data]
        private var buffer = Data()
        private let expecting: Int
        private let conn: NWConnection
        private let finish: () -> Void

        init(pending: [Data], expecting: Int, conn: NWConnection,
             finish: @escaping () -> Void) {
            self.pending = pending; self.expecting = expecting
            self.conn = conn; self.finish = finish
        }

        var received: Data { lock.lock(); defer { lock.unlock() }; return buffer }

        func begin() {
            // NWConnection preserves send ordering, so frames can be queued
            // back-to-back; the proxy consumes exactly the prefix each stage needs.
            lock.lock()
            let frames = pending; pending = []
            lock.unlock()
            for frame in frames {
                conn.send(content: frame, completion: .contentProcessed { _ in })
            }
            read()
        }

        private func read() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [self] data, _, isDone, _ in
                lock.lock()
                if let data { buffer += data }
                let total = buffer.count
                lock.unlock()
                if total >= expecting || isDone { finish() } else { read() }
            }
        }
    }

    func testSocks5ConnectReachesOrigin() throws {
        let (origin, originPort) = try startEchoServer()
        defer { origin.cancel() }
        let proxy = try startProxy(port: 11080)
        defer { proxy.stop() }

        // greeting: VER=5, 1 method, no-auth
        let greeting = Data([0x05, 0x01, 0x00])
        // request: CONNECT to 127.0.0.1 (ATYP=1) : originPort
        let request = Data([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                            UInt8(originPort >> 8), UInt8(originPort & 0xFF)])
        let payload = Data("PING".utf8)

        // 2 bytes greeting reply + 10 bytes connect reply + 4 bytes "PONG"
        let got = try exchange(port: 11080, send: [greeting, request, payload], expecting: 16)

        XCTAssertGreaterThanOrEqual(got.count, 12, "short reply: \(got as NSData)")
        XCTAssertEqual(Array(got.prefix(2)), [0x05, 0x00], "method-selection reply")
        XCTAssertEqual(got[2], 0x05, "connect reply version")
        XCTAssertEqual(got[3], 0x00, "connect reply must report success")
        XCTAssertTrue(got.suffix(4) == Data("PONG".utf8),
                      "origin bytes did not come back through the proxy")
    }

    func testHTTPConnectReachesOrigin() throws {
        let (origin, originPort) = try startEchoServer()
        defer { origin.cancel() }
        let proxy = try startProxy(port: 11081)
        defer { proxy.stop() }

        let req = Data("CONNECT 127.0.0.1:\(originPort) HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        let got = try exchange(port: 11081, send: [req, Data("PING".utf8)], expecting: 43)
        let text = String(data: got, encoding: .utf8) ?? ""
        XCTAssertTrue(text.hasPrefix("HTTP/1.1 200"), "got: \(text)")
        XCTAssertTrue(text.hasSuffix("PONG"), "origin bytes did not come back: \(text)")
    }

    func testRejectsNonConnectHTTPMethod() throws {
        let proxy = try startProxy(port: 11082)
        defer { proxy.stop() }
        let req = Data("GET http://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        let got = try exchange(port: 11082, send: [req], expecting: 20)
        XCTAssertTrue((String(data: got, encoding: .utf8) ?? "").contains("405"))
    }

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

    /// Changing the upstream on a running proxy must not rebind the socket.
    /// `NWListener.cancel()` is asynchronous, so a stop-then-start on the same
    /// port raced its own cancel and lost with "Address already in use" —
    /// leaving the toggle on and nothing listening. The tell is the socket
    /// leaving the listening state at all: a live proxy that reports stopped or
    /// failed while being reconfigured has already dropped the port.
    func testChangingUpstreamNeverDropsTheListener() throws {
        let settings = RelayTunnelSettings(
            enabled: true,
            workerURL: try XCTUnwrap(URL(string: "https://example.workers.dev")),
            token: "t")
        let proxy = try XCTUnwrap(LocalProxy(port: 18082, upstream: .direct))

        let listening = expectation(description: "listening")
        listening.assertForOverFulfill = false
        proxy.start(upstream: .direct) { state in
            if case .listening = state { listening.fulfill() }
        }
        wait(for: [listening], timeout: 5)
        defer { proxy.stop() }

        // The switch the app makes when the Worker toggle is flipped.
        let seen = StateRecorder()
        proxy.start(upstream: .worker(settings)) { seen.record($0) }

        // Long enough for an asynchronous cancel to land, had one been asked for.
        let settled = expectation(description: "settled")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { settled.fulfill() }
        wait(for: [settled], timeout: 5)

        XCTAssertEqual(proxy.state, .listening(port: 18082),
                       "the proxy stopped listening while only its upstream changed")
        XCTAssertTrue(seen.states.allSatisfy { if case .listening = $0 { return true } else { return false } },
                      "the socket left the listening state: \(seen.states)")
    }

    /// The WARP switch starts the proxy, then WARP's first state change starts
    /// it again before the bind reports ready. Log 2026-09-15: that second call
    /// cancelled the pending listener and logged "stopping" + "listenerCancelled".
    func testSecondStartWhileBindPendingKeepsTheListener() throws {
        let proxy = try XCTUnwrap(LocalProxy(port: 18083, upstream: .direct))
        defer { proxy.stop() }
        let seen = StateRecorder()
        proxy.start(upstream: .direct) { seen.record($0) }
        proxy.start(upstream: .socks5(host: "127.0.0.1", port: 1)) { seen.record($0) }

        let settled = expectation(description: "settled")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { settled.fulfill() }
        wait(for: [settled], timeout: 5)

        XCTAssertEqual(proxy.state, .listening(port: 18083))
        XCTAssertEqual(seen.states, [.listening(port: 18083)],
                       "the pending bind was torn down and redone: \(seen.states)")
    }

    /// The state callback fires on the listener's queue, so the test's own view
    /// of it needs a lock rather than an array.
    private final class StateRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var seen: [LocalProxy.State] = []
        func record(_ s: LocalProxy.State) { lock.lock(); seen.append(s); lock.unlock() }
        var states: [LocalProxy.State] { lock.lock(); defer { lock.unlock() }; return seen }
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
}
#endif
