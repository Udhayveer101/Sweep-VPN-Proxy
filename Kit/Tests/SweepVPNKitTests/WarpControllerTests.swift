#if os(macOS)
import XCTest
import SweepVPNCore
@testable import SweepVPNKit
@testable import SweepVPNUI

/// No real usque process: log lines below are real output from usque 2026-09.
final class WarpControllerTests: XCTestCase {

    /// A lock around one Int, so the state callback can count from any thread.
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func bump() -> Int { lock.lock(); defer { lock.unlock() }; n += 1; return n }
    }

    func tmpDir() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("warp-test-\(UUID().uuidString)", isDirectory: true)
    }

    func testClassifiesRealLogLines() {
        XCTAssertEqual(WarpController.classify("2026/09/11 23:55:42 IST SOCKS proxy listening on 127.0.0.1:1080"), .listening)
        XCTAssertEqual(WarpController.classify("2026/09/11 23:55:51 IST Connected to MASQUE server"), .connected)
        XCTAssertEqual(WarpController.classify("2026/09/11 IST Failed to connect tunnel: timeout"), .error)
        XCTAssertNil(WarpController.classify("2026/09/11 23:55:42 IST Tunnel idle. Waiting for outbound activity before reconnecting..."))
        XCTAssertEqual(WarpController.classify("2026/09/13 IST Tunnel connection lost: io: read/write on closed pipe. Reconnecting..."), .lost)
    }

    func testArgumentsUseSpoofedSNIOverHTTP2OnLoopback() {
        let dir = tmpDir()
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: dir)
        XCTAssertEqual(w.arguments, ["-c", dir.appendingPathComponent("config.json").path, "socks",
                                     "-s", "example.com", "--http2",
                                     "--always-reconnect", "-k", "5s", "--dns-timeout", "15s",
                                     "-d", "1.1.1.1", "-d", "1.0.0.1",
                                     "-b", "127.0.0.1", "-p", "1081"])
    }

    /// Real lines from the wedged session of 2026-09-13.
    ///
    /// The rule these pin down: usque reconnecting on its own must cost nothing,
    /// and only usque *failing* to reconnect may relaunch the child. Before
    /// v1.3.0 the first write error relaunched it outright, which is the
    /// regression testers reported.
    func testALossThatHealsItselfDoesNotRestartAnything() {
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        w.pretendRunningForTests()
        w.ingest(log: "2026/09/13 IST Tunnel connection lost: connection closed while writing to IP connection: io: read/write on closed pipe. Reconnecting...\n")
        XCTAssertTrue(w.isAwaitingRecovery, "a loss should start the clock")
        w.ingest(log: "2026/09/13 IST Connected to MASQUE server\n")
        XCTAssertFalse(w.isAwaitingRecovery, "usque healed it; the clock must stand down")
        XCTAssertFalse(w.state.isFailed)
    }

    /// The write error that used to relaunch the child immediately. It may arm
    /// the deadline, never more.
    func testAWriteErrorOnlyArmsTheDeadline() {
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        let writeFail = "2026/09/13 IST Error writing to IP connection: connect-ip: failed to send datagram capsule: io: read/write on closed pipe, continuing..."

        // No child running: nothing to supervise, so nothing is armed.
        XCTAssertFalse(w.noteFailure(writeFail))

        w.pretendRunningForTests()
        XCTAssertTrue(w.noteFailure(writeFail))
        // Already waiting: a burst of further errors must not pile up timers.
        XCTAssertFalse(w.noteFailure(writeFail))
        XCTAssertFalse(w.noteFailure(writeFail))
        XCTAssertTrue(w.isAwaitingRecovery)
        w.noteRecovered()
        XCTAssertFalse(w.isAwaitingRecovery)
    }

    /// A line split across two pipe reads must still be classified once.
    func testALineSplitAcrossReadsIsStillSeen() {
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        w.ingest(log: "2026/09/11 23:55:42 IST SOCKS proxy listen")
        XCTAssertNotEqual(w.state, .running, "half a line is not an event")
        w.ingest(log: "ing on 127.0.0.1:1081\n")
        XCTAssertEqual(w.state, .running)
    }

    func testMissingConfigFailsWithoutLaunching() {
        let dir = tmpDir()
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: dir)
        w.start { _ in }
        guard case .failed(let why) = w.state else { return XCTFail("state \(w.state)") }
        XCTAssertTrue(why.contains("WARP setup"))
        let mode = try? FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o700)
    }

    func testRunningOnlyAfterListenerLine() {
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        w.ingest(log: "IST Establishing MASQUE connection to 162.159.198.2:443\n")
        XCTAssertNotEqual(w.state, .running)
        w.ingest(log: "IST SOCKS proxy listening on 127.0.0.1:1081\n")
        XCTAssertEqual(w.state, .running)
    }
}

@MainActor
final class WarpUpstreamTests: XCTestCase {
    func makeModel() -> VPNViewModel {
        VPNViewModel(configurator: VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel"))
    }

    func testRunningWarpIsTheUpstream() {
        let m = makeModel()
        m.options.warpEnabled = true
        m.warpState = .running
        XCTAssertEqual(m.currentUpstream(), .socks5(host: "127.0.0.1", port: 1081))
        XCTAssertEqual(m.proxyUpstreamLabel, "WARP")
    }

    /// Used to fall through to .direct, which quietly sent traffic the user had
    /// routed through WARP straight out to the ISP whenever WARP was starting,
    /// restarting after a wedge, or failed. A refused dial on 1081 is the honest
    /// answer.
    func testWarpNotReadyFailsClosedRatherThanGoingDirect() {
        let m = makeModel()
        m.options.warpEnabled = true
        for st: WarpController.State in [.stopped, .starting, .running, .failed("wedged")] {
            m.warpState = st
            XCTAssertEqual(m.currentUpstream(), .socks5(host: "127.0.0.1", port: 1081),
                           "leaked to \(m.currentUpstream()) while warp was \(st)")
        }
    }


}
#endif
