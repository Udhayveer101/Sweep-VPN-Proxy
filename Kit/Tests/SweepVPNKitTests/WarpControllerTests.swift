#if os(macOS)
import XCTest
import SweepVPNCore
@testable import SweepVPNKit
@testable import SweepVPNUI

/// No real usque process: log lines below are real output from usque 2026-09.
final class WarpControllerTests: XCTestCase {

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
                                     "--always-reconnect", "--dns-timeout", "5s",
                                     "-d", "1.1.1.1", "-d", "1.0.0.1",
                                     "-b", "127.0.0.1", "-p", "1081"])
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

    func testWarpNotReadyFallsThrough() {
        let m = makeModel()
        m.options.warpEnabled = true
        m.warpState = .starting
        XCTAssertEqual(m.currentUpstream(), .direct)
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
