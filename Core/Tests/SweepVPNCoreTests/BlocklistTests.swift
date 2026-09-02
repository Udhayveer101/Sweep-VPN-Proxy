import XCTest
@testable import SweepVPNCore

/// Suffix matching on a blocklist is a security boundary: a sloppy match either
/// blocks sites the user did not ask to block, or lets blocked ones through.
final class BlocklistTests: XCTestCase {
    private let rules = ["evil.com", "ads.example.net"]

    func testMatchesExactAndSubdomains() {
        XCTAssertTrue(FilterPolicy.isBlocked("evil.com", by: rules))
        XCTAssertTrue(FilterPolicy.isBlocked("tracker.evil.com", by: rules))
        XCTAssertTrue(FilterPolicy.isBlocked("a.b.ads.example.net", by: rules))
        XCTAssertTrue(FilterPolicy.isBlocked("EVIL.COM", by: rules), "matching is case-insensitive")
    }

    func testDoesNotMatchAcrossLabelBoundaries() {
        // Plain hasSuffix would wrongly block this one.
        XCTAssertFalse(FilterPolicy.isBlocked("notevil.com", by: rules))
        // And plain hasPrefix would wrongly let this one through.
        XCTAssertFalse(FilterPolicy.isBlocked("example.net", by: rules))
    }

    /// The attack the boundary check exists to stop.
    func testDoesNotMatchWhenRuleIsASubstringOfAnAttackerDomain() {
        XCTAssertFalse(FilterPolicy.isBlocked("evil.com.attacker.net", by: rules))
    }

    func testEmptyListBlocksNothing() {
        XCTAssertFalse(FilterPolicy.isBlocked("evil.com", by: []))
        XCTAssertFalse(FilterPolicy.isBlocked("evil.com", by: ["", "  ", "."]))
    }

    /// The load-bearing behaviour: blocked with the tunnel down and the kill
    /// switch off, which is where an in-tunnel DNS filter can do nothing.
    func testBlocklistAppliesWithTunnelDownAndKillSwitchOff() {
        var options = SecurityPolicyOptions()
        options.killSwitchEnabled = false
        options.blockedDomains = rules
        let policy = FilterPolicy(options: options, tunnelInterface: nil, tunnelIsUp: false)

        XCTAssertEqual(policy.verdict(for: .init(interfaceName: "en0", remoteAddress: "ads.example.net")),
                       .drop)
        XCTAssertEqual(policy.verdict(for: .init(interfaceName: "en0", remoteAddress: "apple.com")),
                       .allow, "an unblocked host is unaffected when the kill switch is off")
    }

    func testLoopbackIsNeverBlocked() {
        var options = SecurityPolicyOptions()
        options.blockedDomains = ["localhost"]
        let policy = FilterPolicy(options: options)
        XCTAssertEqual(policy.verdict(for: .init(interfaceName: "lo0", remoteAddress: "localhost",
                                                 isLoopback: true)), .allow)
    }
}
