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

    // MARK: - Replacing the running app

    private func fakeBundle(_ dir: URL, _ name: String, marker: String) throws -> URL {
        let app = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        try marker.write(to: app.appendingPathComponent("marker"), atomically: true, encoding: .utf8)
        return app
    }

    private func startSwap(_ dir: URL, appLives: String = "1", ticks: Int) throws -> (bundle: URL, state: URL, swap: Process) {
        let bundle = try fakeBundle(dir, "Sweep VPN.app", marker: "old")
        let staged = try fakeBundle(dir, UpdateChecker.stagingURL(for: bundle).lastPathComponent, marker: "new")
        let state = dir.appendingPathComponent("state")
        let app = Process()
        app.executableURL = URL(fileURLWithPath: "/bin/sleep")
        app.arguments = [appLives]
        try app.run()
        let swap = try UpdateChecker.swapAfterExit(staged: staged, version: "9.9", bundle: bundle,
                                                   pid: app.processIdentifier, opener: "/usr/bin/true",
                                                   state: state, ticks: ticks)
        return (bundle, state, swap)
    }

    private func marker(_ bundle: URL) -> String? {
        try? String(contentsOf: bundle.appendingPathComponent("marker"), encoding: .utf8)
    }

    /// The swap must wait for the old process, and once the new version has
    /// confirmed it started, leave exactly one bundle holding the new contents.
    func testSwapReplacesTheBundleOnceTheAppExits() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (bundle, state, swap) = try startSwap(dir, ticks: 50)
        usleep(300_000)
        XCTAssertEqual(marker(bundle), "old", "swapped while the app was still running")
        while marker(bundle) != "new", swap.isRunning { usleep(50_000) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: bundle.path + ".old"),
                      "the old bundle must survive until the new one confirms")

        // What the new version does at launch.
        let outcome = UpdateChecker(current: "9.9", session: session(), defaults: defaults())
            .finishPendingUpdate(state: state)
        XCTAssertEqual(outcome, .updated("9.9"))
        swap.waitUntilExit()

        XCTAssertEqual(swap.terminationStatus, 0)
        XCTAssertEqual(marker(bundle), "new")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted(),
                       ["Sweep VPN.app", "state"])
    }

    /// A new version that never confirms is taken out again, and the restored
    /// one reports it and stops offering that release unprompted.
    func testSwapRollsBackWhenTheNewVersionNeverStarts() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (bundle, state, swap) = try startSwap(dir, appLives: "0.2", ticks: 3)
        swap.waitUntilExit()

        XCTAssertEqual(marker(bundle), "old")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted(),
                       ["Sweep VPN.app", "state"])
        let store = defaults()
        let old = UpdateChecker(current: "1.3.0", session: session(), defaults: store)
        guard case .failed(let version, let reason)? = old.finishPendingUpdate(state: state) else {
            return XCTFail("the restored version must learn the update failed")
        }
        XCTAssertEqual(version, "9.9")
        XCTAssertTrue(reason.contains("did not start"), reason)
        XCTAssertNil(old.finishPendingUpdate(state: state), "reported once")

        // No loop: the failed release is not offered again by the daily check.
        store.set("1.4.0", forKey: UpdateChecker.failedVersionKey)
        feed(release("v1.4.0", asset: "SweepVPN-1.4.0.dmg"))
        let quiet = await old.check()
        XCTAssertNil(quiet)
        let asked = await old.check(force: true)
        XCTAssertEqual(asked?.version, "1.4.0")
    }

    /// A copy that cannot write its own folder falls back to the DMG rather
    /// than failing: `stage` answers nil before it touches the image.
    func testStageDeclinesWhereItCannotWrite() throws {
        let checker = UpdateChecker(current: "1.0.0", session: session(), defaults: defaults())
        let dmg = URL(fileURLWithPath: "/nonexistent.dmg")
        XCTAssertNil(try checker.stage(dmg, replacing: URL(fileURLWithPath: "/System/Applications/Mail.app")))
        XCTAssertNil(try checker.stage(dmg, replacing: URL(fileURLWithPath:
            "/private/var/folders/x/AppTranslocation/y/d/Sweep VPN.app")))
    }

    /// Against a real release image: `SWEEP_DMG=build/release/SweepVPN-X.dmg`.
    func testStagesARealRelease() throws {
        guard let path = ProcessInfo.processInfo.environment["SWEEP_DMG"] else {
            throw XCTSkip("set SWEEP_DMG to a notarised release image")
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let bundle = try fakeBundle(dir, "Sweep VPN.app", marker: "old")
        let checker = UpdateChecker(current: "1.0.0", session: session(), defaults: defaults())
        let staged = try XCTUnwrap(try checker.stage(URL(fileURLWithPath: path), replacing: bundle))
        XCTAssertTrue(UpdateChecker.signedByUs(staged))
        XCTAssertTrue(FileManager.default.fileExists(atPath: staged.appendingPathComponent("Contents/MacOS").path))
    }

    /// The whole path against the live feed, short of quitting a real app:
    /// `SWEEP_UPDATE_FROM=2.3 swift test --filter testUpdatesFromTheLiveFeed`
    /// finds the newest release, downloads and verifies it, stages it over a
    /// stand-in bundle, swaps, and checks the bundle now holds that version.
    func testUpdatesFromTheLiveFeed() async throws {
        guard let from = ProcessInfo.processInfo.environment["SWEEP_UPDATE_FROM"] else {
            throw XCTSkip("set SWEEP_UPDATE_FROM to an older version")
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let bundle = try fakeBundle(dir, "Sweep VPN.app", marker: "old")
        let state = dir.appendingPathComponent("state")
        let checker = UpdateChecker(current: from, session: .shared, defaults: defaults())

        let found = await checker.check(force: true)
        let update = try XCTUnwrap(found, "the feed offers nothing newer than \(from)")
        XCTAssertTrue(update.asset.lastPathComponent.hasSuffix(".dmg"), "picked \(update.asset)")
        let dmg = try await checker.download(update)
        let staged = try XCTUnwrap(try checker.stage(dmg, replacing: bundle))
        let swap = try UpdateChecker.swapAfterExit(staged: staged, version: update.version, bundle: bundle,
                                                   pid: 0x7ffffff0, opener: "/usr/bin/true",
                                                   state: state, ticks: 100)
        let info = bundle.appendingPathComponent("Contents/Info.plist")
        while !FileManager.default.fileExists(atPath: info.path), swap.isRunning { usleep(50_000) }
        let plist = try XCTUnwrap(NSDictionary(contentsOf: info))
        XCTAssertEqual(plist["CFBundleShortVersionString"] as? String, update.version)
        XCTAssertTrue(UpdateChecker.signedByUs(bundle))
        // The new version's launch-time confirmation.
        XCTAssertEqual(UpdateChecker(current: update.version, session: .shared, defaults: defaults())
            .finishPendingUpdate(state: state), .updated(update.version))
        swap.waitUntilExit()
        XCTAssertEqual(swap.terminationStatus, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: bundle.path + ".old"))
        print("live update \(from) -> \(update.version) from \(update.asset.lastPathComponent)")
    }
}
#endif
