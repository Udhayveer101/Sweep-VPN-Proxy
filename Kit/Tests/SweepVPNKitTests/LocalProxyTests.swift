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
}
#endif
