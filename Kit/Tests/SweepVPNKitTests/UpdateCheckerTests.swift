#if os(macOS)
import XCTest
import CryptoKit
@testable import SweepVPNKit

/// Serves a canned releases feed, so the picking rules are exercised without
/// hitting GitHub. Reuses `StubProtocol` from ConfigFetcherTests.
final class UpdateCheckerTests: XCTestCase {

    override func setUp() {
        StubProtocol.payload = nil
        StubProtocol.status = 200
        StubProtocol.failure = nil
    }

    private func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: config)
    }

    private func defaults() -> UserDefaults {
        let d = UserDefaults(suiteName: "update-tests-\(UUID().uuidString)")!
        return d
    }

    private func release(_ tag: String, asset: String) -> String {
        """
        {"tag_name":"\(tag)","body":"notes","draft":false,"prerelease":false,
         "assets":[{"name":"\(asset)","browser_download_url":"https://example.invalid/\(asset)"},
                   {"name":"\(asset).sha256","browser_download_url":"https://example.invalid/\(asset).sha256"}]}
        """
    }

    private func feed(_ releases: String...) {
        StubProtocol.payload = "[\(releases.joined(separator: ","))]".data(using: .utf8)
    }

    func testOffersANewerRelease() async {
        feed(release("v1.4.0", asset: "SweepVPN-1.4.0.dmg"))
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertEqual(update?.version, "1.4.0")
        XCTAssertEqual(update?.digest.lastPathComponent, "SweepVPN-1.4.0.dmg.sha256")
    }

    func testSameOrOlderIsNotAnUpdate() async {
        feed(release("v1.3.0", asset: "SweepVPN-1.3.0.dmg"),
             release("v1.2.0", asset: "SweepVPN-1.2.0.dmg"))
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertNil(update)
    }

    /// Both products publish into one release list; the Mac must never offer
    /// itself a Windows build just because it was tagged more recently.
    func testIgnoresTheOtherPlatformsTag() async {
        feed(release("windows-v9.9.9", asset: "SweepVPN-9.9.9-windows-x64.exe"))
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertNil(update)
    }

    func testPicksTheHighestNotTheFirst() async {
        feed(release("v1.4.0", asset: "SweepVPN-1.4.0.dmg"),
             release("v1.10.0", asset: "SweepVPN-1.10.0.dmg"),
             release("v1.5.0", asset: "SweepVPN-1.5.0.dmg"))
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertEqual(update?.version, "1.10.0")
    }

    func testReleaseWithoutADigestIsSkipped() async {
        StubProtocol.payload = """
        [{"tag_name":"v1.4.0","body":"","draft":false,"prerelease":false,
          "assets":[{"name":"SweepVPN-1.4.0.dmg","browser_download_url":"https://example.invalid/x.dmg"}]}]
        """.data(using: .utf8)
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertNil(update)
    }

    func testLaterSuppressesTheOfferUntilItExpires() async {
        let store = defaults()
        let checker = UpdateChecker(current: "1.3.0", session: session(), defaults: store)
        feed(release("v1.4.0", asset: "SweepVPN-1.4.0.dmg"))
        let now = Date()
        checker.snooze(now: now)
        var update = await checker.check(now: now.addingTimeInterval(3600))
        XCTAssertNil(update, "snoozed")
        update = await checker.check(now: now.addingTimeInterval(25 * 3600))
        XCTAssertEqual(update?.version, "1.4.0", "offer comes back after 24h")
        update = await checker.check(force: true, now: now)
        XCTAssertEqual(update?.version, "1.4.0", "an explicit check ignores the snooze")
    }

    func testOfflineIsNotAnError() async {
        StubProtocol.failure = URLError(.notConnectedToInternet)
        let update = await UpdateChecker(current: "1.3.0", session: session(),
                                         defaults: defaults()).check()
        XCTAssertNil(update)
    }

    // MARK: - Digest

    func testDigestMismatchIsRefused() async {
        let payload = Data("not the real dmg".utf8)
        StubProtocol.payload = payload
        let update = UpdateChecker.Update(
            version: "1.4.0", notes: "",
            asset: URL(string: "https://example.invalid/SweepVPN-1.4.0.dmg")!,
            digest: URL(string: "https://example.invalid/SweepVPN-1.4.0.dmg.sha256")!)
        // Every request returns `payload`, so the digest body is garbage too.
        do {
            _ = try await UpdateChecker(current: "1.3.0", session: session(),
                                        defaults: defaults()).download(update)
            XCTFail("an unverified installer must never be accepted")
        } catch {
            XCTAssertEqual(error as? UpdateChecker.UpdateError, .digestMismatch)
        }
    }

    func testDigestParsing() {
        let hex = SHA256.hash(data: Data("x".utf8)).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(UpdateChecker.expectedDigest(from: Data("\(hex)  SweepVPN-1.4.0.dmg\n".utf8)), hex)
        XCTAssertNil(UpdateChecker.expectedDigest(from: Data("garbage\n".utf8)))
    }

    func testVersionOrdering() {
        XCTAssertTrue(UpdateChecker.isNewer("1.10.0", than: "1.9.0"))
        XCTAssertTrue(UpdateChecker.isNewer("1.4", than: "1.3.9"))
        XCTAssertFalse(UpdateChecker.isNewer("1.4.0", than: "1.4"))
        XCTAssertFalse(UpdateChecker.isNewer("1.3.0", than: "1.3.0"))
    }
}
#endif
