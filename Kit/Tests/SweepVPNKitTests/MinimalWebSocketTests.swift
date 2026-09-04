#if os(macOS)
import XCTest
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
}
#endif
