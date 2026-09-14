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
    func testWriteFailureOnAClosedPipeIsAWedgeAndABurstOfDialFailuresIsToo() {
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        let t0 = Date()
        let writeFail = "2026/09/13 IST Error writing to IP connection: connect-ip: failed to send datagram capsule: io: read/write on closed pipe, continuing..."
        let dialFail = "2026/09/13 IST SOCKS TCP handle from 127.0.0.1:60777 failed: dial: lookup example.com. on 1.1.1.1:53: read udp 1.2.3.4:29805: i/o timeout"

        // No child running: nothing to restart.
        XCTAssertFalse(w.noteFailure(writeFail, now: t0))

        w.pretendRunningForTests()
        XCTAssertTrue(w.noteFailure(writeFail, now: t0))
        // Second wedge inside the floor is swallowed, so a wedge loop cannot spin.
        w.pretendRunningForTests()                      // the relaunch finished
        XCTAssertFalse(w.noteFailure(writeFail, now: t0.addingTimeInterval(5)))
        XCTAssertTrue(w.noteFailure(writeFail, now: t0.addingTimeInterval(21)))

        // Dial failures: three is churn, four inside the window is the wedge.
        let w2 = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        w2.pretendRunningForTests()
        XCTAssertFalse(w2.noteFailure(dialFail, now: t0))
        XCTAssertFalse(w2.noteFailure(dialFail, now: t0.addingTimeInterval(1)))
        XCTAssertFalse(w2.noteFailure(dialFail, now: t0.addingTimeInterval(2)))
        XCTAssertTrue(w2.noteFailure(dialFail, now: t0.addingTimeInterval(3)))

        // Spread wider than the window, the same four are just churn.
        let w3 = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: tmpDir())
        w3.pretendRunningForTests()
        for i in 0..<4 {
            XCTAssertFalse(w3.noteFailure(dialFail, now: t0.addingTimeInterval(Double(i) * 11)))
        }
    }

    func testMissingConfigFailsWithoutLaunching() {
        let dir = tmpDir()
        let w = WarpController(executable: URL(fileURLWithPath: "/usr/bin/false"),
                               socksPort: 1081, sni: "example.com", directory: dir)
        w.start { _ in }
        guard case .failed(let why) = w.state else { return XCTFail("state \(w.state)") }
        XCTAssertTrue(why.contains("No WARP registration"))
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
        m.options.torEnabled = true          // WARP wins even if both flags leak through
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

    func testEnablingTorTurnsWarpOff() {
        let m = makeModel()
        m.options.warpEnabled = true
        m.setTor(enabled: true)
        XCTAssertFalse(m.options.warpEnabled)
        m.setTor(enabled: false)
    }

    func testEnablingWarpTurnsTorOff() {
        let m = makeModel()
        m.options.torEnabled = true
        m.setWarp(enabled: true)
        XCTAssertFalse(m.options.torEnabled)
        XCTAssertTrue(m.options.warpEnabled)
        m.setWarp(enabled: false)
    }
}
#endif
