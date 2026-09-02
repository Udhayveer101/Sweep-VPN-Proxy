#if os(macOS)
import XCTest
@testable import SweepVPNKit

/// Lines below are real output from tor 0.4.9.11 (the bundled version).
final class TorControllerTests: XCTestCase {

    func testParsesRealBootstrapLines() {
        let cases: [(String, Int, String)] = [
            ("Sep 02 14:02:11.000 [notice] Bootstrapped 0% (starting): Starting", 0, "Starting"),
            ("Sep 02 14:02:12.000 [notice] Bootstrapped 5% (conn): Connecting to a relay", 5, "Connecting to a relay"),
            ("Sep 02 14:02:20.000 [notice] Bootstrapped 100% (done): Done", 100, "Done"),
        ]
        for (line, percent, summary) in cases {
            let parsed = TorController.parseBootstrap(line)
            XCTAssertEqual(parsed?.percent, percent, "line: \(line)")
            XCTAssertEqual(parsed?.summary, summary, "line: \(line)")
        }
    }

    func testIgnoresNonBootstrapLines() {
        XCTAssertNil(TorController.parseBootstrap("Sep 02 [notice] Opening Socks listener on 127.0.0.1:9150"))
        XCTAssertNil(TorController.parseBootstrap(""))
        // Must not crash or half-parse a malformed percentage.
        XCTAssertNil(TorController.parseBootstrap("[notice] Bootstrapped xx% (conn): nope"))
    }

    /// Guards the ordering guarantee: Tor is only "running" at a full bootstrap.
    /// Reporting running at 99% would route traffic into a circuit that is not built.
    func testOnlyReportsRunningAtFullBootstrap() throws {
        guard let tor = TorController() else {
            throw XCTSkip("no bundled tor in this build; run Tools/bundle-tor.sh")
        }
        tor.ingest(log: "[notice] Bootstrapped 99% (almost): Almost there\n")
        XCTAssertNotEqual(tor.state, .running)
        tor.ingest(log: "[notice] Bootstrapped 100% (done): Done\n")
        XCTAssertEqual(tor.state, .running)
    }
}
#endif
