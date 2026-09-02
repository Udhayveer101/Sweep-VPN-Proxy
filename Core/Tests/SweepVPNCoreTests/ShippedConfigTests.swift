import XCTest
import CryptoKit
@testable import SweepVPNCore

/// Guards the *actual* file that ships in the app bundle.
///
/// History this exists to prevent repeating: the shipped bundle once contained
/// two invented servers — `NL-FREE#1` and `JP-FREE#3`, labelled "Proton VPN",
/// with WireGuard keys that were keyboard walks (`…QEjT1yF8pBZ0mXvNqLr3…`
/// decodes from `qwertyuiop`/`asdfghjkl`). Nothing was listening on either
/// address, so no rung could ever authenticate, the provider failed closed, and
/// on-demand restarted it immediately — which the user saw as the VPN
/// connecting and disconnecting forever. See `StartBackoffTests` for the other
/// half of that fix.
///
/// Shipping *no* servers is a correct, honest state: the app shows its setup
/// guide. Shipping fake ones is not.
final class ShippedConfigTests: XCTestCase {
    private let pinned = "wVOJIuoa32ZZ5lSd8RmCaUOEFQIUYmidxFcK8bhYNYA="

    private var configURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Config/sweep-config.sig.json")
    }

    private func loadShipped() throws -> SignedBundle? {
        guard let data = try? Data(contentsOf: configURL) else { return nil }
        return try JSONDecoder().decode(SignedBundle.self, from: data)
    }

    private func verified(_ signed: SignedBundle) throws -> ConfigBundle {
        let key = try Curve25519.Signing.PublicKey(
            rawRepresentation: XCTUnwrap(Data(base64Encoded: pinned)))
        return try ConfigVerifier.verify(signed, pinnedKey: key, currentVersion: nil,
                                         appBuild: 1, now: Date())
    }

    func testShippedConfigIfPresentVerifiesAgainstThePinnedKey() throws {
        guard let signed = try loadShipped() else {
            // No bundle: the app shows the setup guide. Nothing to verify.
            return
        }
        let bundle = try verified(signed)
        XCTAssertFalse(bundle.servers.isEmpty)
        XCTAssertGreaterThan(bundle.expiresAt, Date(), "shipped config has expired")
        XCTAssertLessThanOrEqual(bundle.minimumAppBuild, 1,
                                 "app CFBundleVersion is 1; a higher floor locks the app out")
    }

    /// The regression guard. A WireGuard public key is 32 random bytes; a key
    /// that decodes to keyboard mashing was typed by a person inventing a
    /// server that does not exist.
    func testNoShippedServerCarriesAFabricatedKey() throws {
        guard let signed = try loadShipped() else { return }
        let bundle = try verified(signed)

        for server in bundle.servers {
            XCTAssertFalse(Self.looksFabricated(server.publicKey),
                           "\(server.id) carries a hand-typed public key — there is no "
                           + "server on the other end of it, and the tunnel will flap forever")
            XCTAssertEqual(Data(base64Encoded: server.publicKey)?.count, 32,
                           "\(server.id) has a public key that is not 32 bytes")
        }
    }

    func testShippedServersDoNotClaimToBeSomeoneElsesInfrastructure() throws {
        guard let signed = try loadShipped() else { return }
        let bundle = try verified(signed)
        for server in bundle.servers where server.provider == "Proton VPN" {
            XCTAssertFalse(server.devicePrivateKey == nil,
                           "\(server.id) claims to be Proton infrastructure but carries no "
                           + "registered device key, so it cannot be what it says it is")
        }
    }

    /// A base64 key whose decoded bytes are a run of adjacent keyboard
    /// characters, rather than anything that came out of a CSPRNG.
    private static func looksFabricated(_ base64: String) -> Bool {
        let walks = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        let haystack = base64.lowercased()
        // The fabricated keys were built by base64-ing keyboard walks, so the
        // walk survives into the encoded form in recognisable chunks.
        for walk in walks {
            for length in stride(from: walk.count, through: 5, by: -1) {
                for start in 0...(walk.count - length) {
                    let idx = walk.index(walk.startIndex, offsetBy: start)
                    let end = walk.index(idx, offsetBy: length)
                    if haystack.contains(walk[idx..<end]) { return true }
                }
            }
        }
        return false
    }

    /// Proves the detector actually catches the key that shipped, so the guard
    /// above cannot quietly rot into always-passing.
    func testFabricatedKeyDetectorCatchesTheKeyThatShipped() {
        XCTAssertTrue(Self.looksFabricated("mXvNqLr3sWdCgHkYuIoPaSdFgHjKlZ0QEjT1yF8pBZ0="))
        XCTAssertTrue(Self.looksFabricated("QEjT1yF8pBZ0mXvNqLr3sWdCgHkYuIoPaSdFgHjKlZ0="))
        // A real Curve25519 public key must not trip it.
        let real = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        XCTAssertFalse(Self.looksFabricated(real))
    }
}
