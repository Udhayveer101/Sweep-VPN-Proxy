#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

/// The framer is hand-written, so the frame parser gets the one check that
/// fails if it drifts: lengths, masking, fragmentation and partial buffers.
final class MinimalWebSocketTests: XCTestCase {

    func testRoundTripsItsOwnFrame() throws {
        let payload = Data((0..<200).map { UInt8($0 % 251) })
        let parsed = try XCTUnwrap(MinimalWebSocket.parseFrame(MinimalWebSocket.frame(payload)))
        // Our own frames are masked, as a client's must be.
        XCTAssertEqual(parsed.payload, payload)
        XCTAssertEqual(parsed.opcode, 0x2)
        XCTAssertTrue(parsed.isFinal)
    }

    func testUnmaskedServerFrame() throws {
        // 0x81 0x03 "abc" — a final text frame, the shape a server sends.
        let frame = Data([0x81, 0x03]) + Data("abc".utf8)
        let parsed = try XCTUnwrap(MinimalWebSocket.parseFrame(frame))
        XCTAssertEqual(parsed.payload, Data("abc".utf8))
        XCTAssertEqual(parsed.consumed, 5)
    }

    func testExtendedLengthAndTrailingBytes() throws {
        // A 400-byte payload uses the 126 form; a second frame follows it, and
        // only the first one may be consumed.
        let payload = Data(repeating: 0x5A, count: 400)
        var buffer = Data([0x82, 126, 0x01, 0x90]) + payload
        buffer.append(contentsOf: [0x82, 0x01, 0x07])
        let parsed = try XCTUnwrap(MinimalWebSocket.parseFrame(buffer))
        XCTAssertEqual(parsed.payload, payload)
        XCTAssertEqual(parsed.consumed, 404)

        let rest = buffer.dropFirst(parsed.consumed)
        let second = try XCTUnwrap(MinimalWebSocket.parseFrame(Data(rest)))
        XCTAssertEqual(second.payload, Data([0x07]))
    }

    func testIncompleteFrameYieldsNil() {
        // The status byte arriving one byte at a time must not be misread as a
        // frame — a truncated read is "not yet", never a message.
        XCTAssertNil(MinimalWebSocket.parseFrame(Data([0x82])))
        XCTAssertNil(MinimalWebSocket.parseFrame(Data([0x82, 0x05, 0x01, 0x02])))
        XCTAssertNil(MinimalWebSocket.parseFrame(Data([0x82, 126, 0x01])))
    }

    func testHeaderTerminatorFoundInBothForms() {
        let crlf = Data("HTTP/1.1 101 x\r\n\r\nAB".utf8)
        XCTAssertEqual(MinimalWebSocket.rangeOfHeaderTerminator(in: crlf)?.upperBound, 18)
        let lf = Data("HTTP/1.1 101 x\n\nAB".utf8)
        XCTAssertEqual(MinimalWebSocket.rangeOfHeaderTerminator(in: lf)?.upperBound, 16)
    }

    // MARK: - Liveness

    /// The failure this exists for: the leg's path goes away, nothing arrives,
    /// and before the keepalive the only thing that noticed was the kernel's
    /// retransmission timer a minute later.
    func testAQuietLegIsDeclaredDead() {
        let queue = DispatchQueue(label: "test.ws.keepalive")
        // Nothing listens on discard here, so nothing will ever arrive — which
        // is the case under test.
        let connection = NWConnection(host: .ipv4(.loopback), port: 9, using: .tcp)
        let socket = MinimalWebSocket(connection: connection, host: "example", path: "/")
        let dead = expectation(description: "reported dead")
        socket.startKeepalive(on: queue, interval: 0.05, idleAfter: 0.2) { dead.fulfill() }
        wait(for: [dead], timeout: 2)
        socket.stopKeepalive()
        connection.cancel()
    }

    func testAStoppedKeepaliveStaysQuiet() {
        let queue = DispatchQueue(label: "test.ws.keepalive.stop")
        let connection = NWConnection(host: .ipv4(.loopback), port: 9, using: .tcp)
        let socket = MinimalWebSocket(connection: connection, host: "example", path: "/")
        let fired = expectation(description: "must not fire")
        fired.isInverted = true
        socket.startKeepalive(on: queue, interval: 0.05, idleAfter: 0.1) { fired.fulfill() }
        socket.stopKeepalive()
        wait(for: [fired], timeout: 0.5)
        connection.cancel()
    }

    // MARK: - Whose failure it was

    /// A close frame is the Worker's verdict on the relay; its absence is our
    /// own leg dropping. Treating the second as the first is what burned a good
    /// relay on every network blip.
    func testCloseCodeDecidesWhetherTheRelayIsGone() {
        XCTAssertEqual(WebSocketTransport.disposition(closeCode: 1000), .relayGone)
        XCTAssertEqual(WebSocketTransport.disposition(closeCode: 1008), .relayGone)
        XCTAssertEqual(WebSocketTransport.disposition(closeCode: 1006), .ourLeg)
        XCTAssertEqual(WebSocketTransport.disposition(closeCode: nil), .ourLeg)
    }

    /// A 5xx is the Worker being broken, not its verdict on the relay behind
    /// it. Getting this wrong is what let one `1101` — the Durable Objects
    /// free-tier duration budget, spent for the day — burn a whole relay pool.
    func testOnlyFiveHundredsCountAsTheWorkerBeingDown() {
        XCTAssertTrue(MinimalWebSocket.isServerError("HTTP/1.1 500 Internal Server Error"))
        XCTAssertTrue(MinimalWebSocket.isServerError("HTTP/1.1 502 Bad Gateway"))
        XCTAssertFalse(MinimalWebSocket.isServerError("HTTP/1.1 426 Upgrade Required"))
        XCTAssertFalse(MinimalWebSocket.isServerError("HTTP/1.1 200 OK"))
        XCTAssertFalse(MinimalWebSocket.isServerError("no status line"))
    }
}
#endif
