#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

final class WorkerStreamTests: XCTestCase {

    /// The path must carry the destination and the token, or the Worker answers
    /// `forbidden` and the failure looks like a dead network.
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
