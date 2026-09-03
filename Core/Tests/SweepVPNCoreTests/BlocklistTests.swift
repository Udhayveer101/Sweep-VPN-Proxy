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

/// Domain rules were matched against the flow's remote *address*, which by the
/// time a flow exists is an IP — so the blocklist advertised in Settings
/// ("blocked at the connection, not just in DNS") silently blocked nothing.
extension BlocklistTests {
    private func policy(blocking domains: [String]) -> FilterPolicy {
        var options = SecurityPolicyOptions()
        options.blockedDomains = domains
        return FilterPolicy(options: options, tunnelIsUp: true)
    }

    func testDomainRuleMatchesTheHostnameNotJustTheAddress() {
        let p = policy(blocking: ["ads.example.com"])
        XCTAssertEqual(p.verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34",
                                            remoteHostname: "ads.example.com")), .drop)
        // Subdomains too, as the settings copy promises.
        XCTAssertEqual(p.verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34",
                                            remoteHostname: "img.ads.example.com")), .drop)
    }

    func testUnrelatedHostnameIsNotBlocked() {
        let p = policy(blocking: ["ads.example.com"])
        XCTAssertEqual(p.verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34",
                                            remoteHostname: "notads.example.com")), .allow)
        XCTAssertEqual(p.verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34",
                                            remoteHostname: "ads.example.com.attacker.net")), .allow)
    }

    /// A literal address in the list must still work — the hostname check is an
    /// addition, not a replacement.
    func testLiteralAddressRuleStillMatches() {
        let p = policy(blocking: ["93.184.216.34"])
        XCTAssertEqual(p.verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34",
                                            remoteHostname: nil)), .drop)
    }
}
