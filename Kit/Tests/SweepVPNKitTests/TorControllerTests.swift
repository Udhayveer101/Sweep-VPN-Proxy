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

    // MARK: - Transport chain

    func testChainTriesCheapTransportsBeforeExpensiveOnes() {
        let chain = TorController.Reachability.chain(userBridges: [])
        XCTAssertEqual(chain.first, .direct, "direct is free and works over the VPN")
        XCTAssertEqual(chain.last, .meek, "meek is slowest, so it goes last")
        XCTAssertTrue(chain.contains(.snowflake))
        // Snowflake must be tried before meek: it is far faster when it works.
        let snowflakeIndex = try? XCTUnwrap(chain.firstIndex(of: .snowflake))
        let meekIndex = try? XCTUnwrap(chain.firstIndex(of: .meek))
        XCTAssertLessThan(snowflakeIndex ?? 99, meekIndex ?? 0)
    }

    /// A user who pasted their own bridges got them from bridges.torproject.org
    /// for this network specifically, so they must be tried before the public
    /// defaults that are already widely blocked.
    func testUserSuppliedBridgesArePreferredOverPublicDefaults() {
        let mine = ["obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0"]
        let chain = TorController.Reachability.chain(userBridges: mine)
        let mineIndex = chain.firstIndex(of: .bridges(mine))
        let defaultsIndex = chain.firstIndex(of: .bridges(TorController.Reachability.defaultBridgeLines))
        XCTAssertNotNil(mineIndex)
        XCTAssertNotNil(defaultsIndex)
        XCTAssertLessThan(mineIndex ?? 99, defaultsIndex ?? 0)
    }

    func testEveryChainStepIsDistinct() {
        let chain = TorController.Reachability.chain(userBridges: ["obfs4 9.9.9.9:1 B cert=y"])
        XCTAssertEqual(chain.count, Set(chain.map(String.init(describing:))).count,
                       "a repeated step wastes a whole stall timeout")
    }
}
#endif
