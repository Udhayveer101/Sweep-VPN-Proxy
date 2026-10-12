#if os(macOS)
import XCTest
@testable import SweepVPNKit
@testable import SweepVPNUI

/// The shell `SystemProxy.command` builds runs as root in the app. Here it runs
/// unprivileged against stand-ins for `networksetup` and `route`, which record
/// what they were asked to do.
final class SystemProxyTests: XCTestCase {

    /// Wi-Fi (en0) carries the default route; Ethernet is plugged in but idle;
    /// Thunderbolt Bridge is disabled. `failing` names a service whose proxy
    /// cannot be set.
    private func run(_ command: String, failing: String = "") throws -> (status: Int32, calls: [String]) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sysproxy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let calls = dir.appendingPathComponent("calls")
        let stubs = [
            "route": "#!/bin/sh\necho '   interface: en0'\n",
            "networksetup": """
            #!/bin/sh
            echo "$*" >> "$CALLS"
            case "$1" in
            -listnetworkserviceorder)
              printf '(1) Ethernet\\n(Hardware Port: Ethernet, Device: en5)\\n\\n(2) Wi-Fi\\n(Hardware Port: Wi-Fi, Device: en0)\\n' ;;
            -listallnetworkservices)
              printf 'An asterisk (*) denotes that a network service is disabled.\\nEthernet\\nWi-Fi\\n*Thunderbolt Bridge\\n' ;;
            -setsocksfirewallproxy) [ "$2" = "$FAILING" ] && exit 1 ;;
            esac
            exit 0

            """,
        ]
        for (name, body) in stubs {
            let url = dir.appendingPathComponent(name)
            try body.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", command]
        p.environment = ["PATH": "\(dir.path):/usr/bin:/bin", "CALLS": calls.path, "FAILING": failing]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        let log = (try? String(contentsOf: calls, encoding: .utf8)) ?? ""
        return (p.terminationStatus, log.split(separator: "\n").map(String.init))
    }

    /// Set on Wi-Fi alone, plugging in Ethernet moved the Mac to a service with
    /// no proxy: everything went out directly under a "Connected" headline.
    func testEnablingCoversEveryEnabledServiceNotJustTheActiveOne() throws {
        let (status, calls) = try run(SystemProxy.command(enabled: true, port: 1080))
        XCTAssertEqual(status, 0)
        for service in ["Wi-Fi", "Ethernet"] {
            XCTAssertTrue(calls.contains("-setsocksfirewallproxy \(service) 127.0.0.1 1080 off"), "\(service): \(calls)")
            XCTAssertTrue(calls.contains("-setsocksfirewallproxystate \(service) on"), "\(service): \(calls)")
        }
        XCTAssertFalse(calls.contains { $0.contains("Thunderbolt") && $0.hasPrefix("-set") },
                       "a disabled service was touched: \(calls)")
    }

    /// The active service is the one traffic is on now, so failing there is a
    /// failure; an idle service that refuses is not.
    func testOnlyTheActiveServiceMustTakeTheSetting() throws {
        XCTAssertNotEqual(try run(SystemProxy.command(enabled: true, port: 1080), failing: "Wi-Fi").status, 0)
        XCTAssertEqual(try run(SystemProxy.command(enabled: true, port: 1080), failing: "Ethernet").status, 0)
    }

    func testEffectiveProxyIsOursOnlyWhenItPointsAtOurPort() {
        let ours: [String: Any] = ["SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 1080]
        XCTAssertTrue(SystemProxy.isEffective(port: 1080, settings: ours))
        XCTAssertFalse(SystemProxy.isEffective(port: 1080, settings: [:]))          // a service with no proxy
        XCTAssertFalse(SystemProxy.isEffective(port: 1080, settings: ours.merging(["SOCKSEnable": 0]) { $1 }))
        XCTAssertFalse(SystemProxy.isEffective(port: 1080, settings: ours.merging(["SOCKSPort": 9050]) { $1 }))
        XCTAssertFalse(SystemProxy.isEffective(port: 1080, settings: nil))
    }
}

@MainActor
final class SystemProxyDriftTests: XCTestCase {
    private func makeModel() -> VPNViewModel {
        VPNViewModel(configurator: VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel"))
    }

    /// The warning must not flip `systemProxyEnabled`: quitting and Disconnect
    /// only undo the setting while it is true, and a Mac left pointing at a
    /// dead listener is offline.
    func testDriftWarnsWithoutForgettingTheSettingIsStillOurs() {
        let m = makeModel()
        m.systemProxyEnabled = true
        m.noteSystemProxy(inForce: false)
        XCTAssertEqual(m.systemProxyError, VPNViewModel.proxyDriftMessage)
        XCTAssertTrue(m.systemProxyEnabled)

        m.noteSystemProxy(inForce: true)       // back on a service that has it
        XCTAssertNil(m.systemProxyError)
    }

    func testNoWarningWhenWeNeverSetTheProxy() {
        let m = makeModel()
        m.noteSystemProxy(inForce: false)
        XCTAssertNil(m.systemProxyError)
    }
}
#endif
