#if os(macOS)
import XCTest
@testable import SweepVPNKit

/// The privileged script is the only thing that knows how setup went, and its
/// log is the only channel back. These are real lines from Tools/gamemode.sh.
final class GameModeTests: XCTestCase {

    func testReadyLineMarksTheTunnelUp() {
        XCTAssertEqual(GameModeController.classify("00:14:02 gamemode: ready"), .ready)
    }

    func testFatalLinesAreDistinguishedFromOrdinaryOutput() {
        XCTAssertEqual(GameModeController.classify("00:14:02 gamemode: FATAL no default gateway; refusing to start"), .fatal)
        XCTAssertNil(GameModeController.classify("00:14:01 gamemode: pinned 162.159.198.2 via 192.168.1.1"))
        XCTAssertNil(GameModeController.classify("2026/09/18 00:14:01 IST Connected to MASQUE server"))
    }

    func testRotationIsReportedButIsNotAFailure() {
        let line = "2026/09/18 00:05:14 IST Retiring MASQUE flow before it ages out; promoting standby"
        XCTAssertEqual(GameModeController.classify(line), .rotated)
    }

    /// A raw script line is not something to show a player.
    func testFatalLinesBecomeSomethingAPlayerCanActetOn() {
        XCTAssertTrue(GameModeController.reason(for: "gamemode: FATAL no default gateway; refusing to start")
            .contains("No network connection"))
        XCTAssertTrue(GameModeController.reason(for: "gamemode: FATAL not running as root")
                        .contains("administrator"))
        XCTAssertTrue(GameModeController.reason(for: "gamemode: FATAL usque exited during setup")
            .contains("WARP setup"))
        XCTAssertTrue(GameModeController.reason(for: "gamemode: FATAL tunnel interface never came up")
            .contains("Try again"))
    }

    /// Rotation is opt-in: the default must not pass a TTL, because rotation
    /// stalls roughly one new connection in twenty (measured 2026-09-18).
    func testStandbyIsTheDefaultAndDoesNotRotate() {
        XCTAssertEqual(GameModeController.Disguise.standby.flowTTL, "0")
        XCTAssertNotEqual(GameModeController.Disguise.rotate.flowTTL, "0")
    }

    /// Gaming mode is useless without the registration the proxy mode uses,
    /// and must say so rather than prompting for a password first.
    func testUnregisteredIsDetectedBeforeAskingForAPassword() {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let controller = GameModeController(script: URL(fileURLWithPath: "/bin/echo"),
                                            usque: URL(fileURLWithPath: "/bin/echo"),
                                            directory: dir)
        XCTAssertFalse(controller.isRegistered)

        let done = expectation(description: "state")
        controller.start { state in
            if case .failed(let why) = state, why.contains("not set up") { done.fulfill() }
        }
        wait(for: [done], timeout: 2)
    }
}
#endif
