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

    /// After "ready", usque dying is restarted with the routes held in the
    /// tunnel; only a restart that keeps failing turns gaming mode off.
    func testUsqueDyingIsRestartedAndOnlyARestartLoopIsFatal() {
        let restart = "00:31:40 gamemode: usque exited; restarting (attempt 1), traffic held"
        XCTAssertEqual(GameModeController.classify(restart), .restarting)
        let gaveUp = "00:32:11 gamemode: FATAL usque would not restart; shutting down"
        XCTAssertEqual(GameModeController.classify(gaveUp), .fatal)
        XCTAssertTrue(GameModeController.reason(for: gaveUp).contains("normal routing back"))
    }

    /// A control file left by a crashed run keeps its root script alive; it
    /// must be withdrawn, and only our own files touched.
    func testStaleRunsAreWithdrawn() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        for name in ["gamemode-ABC.control", "gamemode.control", "config.json"] {
            FileManager.default.createFile(atPath: dir.appendingPathComponent(name).path, contents: nil)
        }
        let c = GameModeController(script: dir, usque: dir, directory: dir, workDir: dir)
        XCTAssertTrue(c.withdrawStaleRuns())
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["config.json"])
        XCTAssertFalse(c.withdrawStaleRuns())
    }

    /// The app writes its own events into the same log; they must never be
    /// mistaken for the script's.
    func testAppLinesAreNotScriptEvents() {
        XCTAssertNil(GameModeController.classify("00:31:40 app: starting sni=example.com"))
        XCTAssertNil(GameModeController.classify("00:31:40 app: usqueExited 00:31:40 gamemode: usque exited; restarting"))
    }

    /// The log is kept across runs, rolled once to .1 when it gets big.
    func testLogHistoryIsKeptAndRolled() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let c = GameModeController(script: dir, usque: dir, directory: dir, workDir: dir)
        let log = dir.appendingPathComponent("gamemode.log")
        c.rollLog()
        try Data("earlier session\n".utf8).write(to: log)
        c.rollLog()
        XCTAssertEqual(try String(contentsOf: log, encoding: .utf8), "earlier session\n")

        try Data(count: Int(GameModeController.logLimit) + 1).write(to: log)
        c.rollLog()
        XCTAssertEqual(try Data(contentsOf: log).count, 0)
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("gamemode.log.1")).count,
                       Int(GameModeController.logLimit) + 1)
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

    /// Each rotation is a new MASQUE session, which resets every open game
    /// connection (measured 2026-09-27). The script must never ask for one.
    func testGamingModeNeverRotates() throws {
        let script = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Tools/gamemode.sh")
        let args = try String(contentsOf: script, encoding: .utf8)
            .split(separator: "\n").filter { $0.contains("ARGS") && !$0.hasPrefix("#") }
        XCTAssertFalse(args.isEmpty)
        for line in args {
            XCTAssertFalse(line.contains("--flow-ttl"), String(line))
            XCTAssertFalse(line.contains("--hot-standby"), String(line))
        }
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
