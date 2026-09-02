import XCTest
import CryptoKit
@testable import SweepVPNCore

/// Verifies the *actual* file that ships in the app bundle against the *actual*
/// key pinned in project.yml. A signed config that fails any of these checks
/// leaves the app with no server list, which the UI reports as "not set up" —
/// indistinguishable, from the outside, from a broken connect button.
final class ShippedConfigTests: XCTestCase {
    private let pinned = "wVOJIuoa32ZZ5lSd8RmCaUOEFQIUYmidxFcK8bhYNYA="

    private func loadShipped() throws -> SignedBundle {
        // Tests run from Core/, the config lives one level up.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Config/sweep-config.sig.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(SignedBundle.self, from: data)
    }

    func testShippedConfigVerifiesAgainstThePinnedKey() throws {
        let signed = try loadShipped()
        let key = try Curve25519.Signing.PublicKey(
            rawRepresentation: XCTUnwrap(Data(base64Encoded: pinned)))

        let bundle = try ConfigVerifier.verify(signed, pinnedKey: key,
                                               currentVersion: nil,
                                               appBuild: 1,
                                               now: Date())
        XCTAssertFalse(bundle.servers.isEmpty)
        XCTAssertGreaterThan(bundle.expiresAt, Date(), "shipped config has expired")
        XCTAssertLessThanOrEqual(bundle.minimumAppBuild, 1,
                                 "app CFBundleVersion is 1; a higher floor locks the app out")
    }

    /// Names what is actually in the shipped list, so a claim about VPN Gate
    /// coverage cannot drift away from the file without a test failing.
    func testShippedListContainsOnlyTheTwoProtonWireGuardServers() throws {
        let signed = try loadShipped()
        let key = try Curve25519.Signing.PublicKey(
            rawRepresentation: XCTUnwrap(Data(base64Encoded: pinned)))
        let bundle = try ConfigVerifier.verify(signed, pinnedKey: key, currentVersion: nil,
                                               appBuild: 1, now: Date())

        XCTAssertEqual(bundle.servers.map(\.id).sorted(), ["JP-FREE#3", "NL-FREE#1"])
        XCTAssertTrue(bundle.servers.allSatisfy { $0.endpoints.allSatisfy { $0.rung == .wireGuardUDP } },
                      "no VPN Gate / OpenVPN endpoint is shipped")
    }
}
