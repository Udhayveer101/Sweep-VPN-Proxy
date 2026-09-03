import XCTest
import NetworkExtension
import SweepVPNCore
@testable import SweepVPNKit
@testable import SweepVPNUI

final class TunnelSettingsMapperTests: XCTestCase {
    let server = Server(id: "s", name: "Stockholm", countryCode: "SE", publicKey: "pk",
                        endpoints: [.init(host: "1.2.3.4", port: 51820, rung: .wireGuardUDP)],
                        dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")

    func testMaskConversion() {
        XCTAssertEqual(TunnelSettingsMapper.mask4(0), "0.0.0.0")
        XCTAssertEqual(TunnelSettingsMapper.mask4(24), "255.255.255.0")
        XCTAssertEqual(TunnelSettingsMapper.mask4(32), "255.255.255.255")
    }

    func testBlackholeSettingsRouteEverythingAndLeaveTheResolverAlone() {
        let s = TunnelSettingsMapper.settings(for: SecurityPolicy().blackholePlan())
        XCTAssertEqual(s.ipv4Settings?.includedRoutes?.first?.destinationAddress, "0.0.0.0")
        XCTAssertEqual(s.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask, "0.0.0.0")
        // No DNS settings at all while connecting — see blackholePlan.
        XCTAssertNil(s.dnsSettings)
        XCTAssertNotNil(s.ipv6Settings, "IPv6 must be captured, not left to the physical interface")
        XCTAssertEqual(s.ipv6Settings?.includedRoutes?.first?.destinationAddress, "::")
    }

    func testConnectedSettingsCaptureIPv6EvenWithoutAnIPv6Address() {
        let plan = SecurityPolicy().connectedPlan(server: server, endpoint: server.endpoints[0])
        let s = TunnelSettingsMapper.settings(for: plan)
        XCTAssertNotNil(s.ipv6Settings)
        XCTAssertEqual(s.dnsSettings?.servers, ["10.64.0.1"])
        XCTAssertEqual(s.ipv4Settings?.addresses, ["10.64.0.2"])
    }
}

final class AdapterFactoryTests: XCTestCase {
    let server = Server(id: "s", name: "s", countryCode: "SE", publicKey: "pk",
                        endpoints: [.init(host: "1.2.3.4", port: 443, rung: .wireGuardTLS)],
                        dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")

    func testKernelRungIsNeverBuiltAsAnAdapter() {
        XCTAssertThrowsError(try AdapterFactory.make(rung: .ikev2, server: server,
                                                     privateKeyBase64: "k", presharedKeyBase64: nil,
                                                     keepalive: 25)) {
            XCTAssertEqual($0 as? AdapterFactoryError, .rungNotImplemented(.ikev2))
        }
    }

    func testMissingEndpointFails() {
        XCTAssertThrowsError(try AdapterFactory.make(rung: .wireGuardUDP, server: server,
                                                     privateKeyBase64: "k", presharedKeyBase64: nil,
                                                     keepalive: 25)) {
            XCTAssertEqual($0 as? AdapterFactoryError, .noEndpoint(.wireGuardUDP))
        }
    }

    func testShippedRungsCoverEveryFailureModeAndExcludeTheKernelOne() {
        // The WireGuard ladder is the same on every platform.
        XCTAssertEqual(Set(AdapterFactory.implementedRungs.filter(\.isOwnWireGuardTunnel)),
                       Set([.wireGuardUDP, .wireGuardUDP443, .wireGuardQUIC,
                            .wireGuardTLS, .shadowsocks2022, .wireGuardTCP]))

        // OpenVPN 3 is linked on macOS only so far, so the OpenVPN rungs must
        // be offered there and must NOT be offered anywhere they cannot run —
        // a listed rung the user cannot reach is exactly the kind of promise
        // this suite exists to prevent.
        #if os(macOS)
        XCTAssertTrue(AdapterFactory.implementedRungs.isSuperset(of: [.openVPNUDP, .openVPNTCP]))
        #else
        XCTAssertTrue(AdapterFactory.implementedRungs.isDisjoint(with: [.openVPNUDP, .openVPNTCP]))
        #endif
        XCTAssertFalse(AdapterFactory.implementedRungs.contains(.ikev2),
                       "IKEv2 is a kernel profile, not a packet-tunnel adapter")
        // IKEv2 is no longer offered at all. IKEv2Configurator exists but nothing
        // calls it, so listing the rung promised a fallback that could never
        // engage — and installing it would overwrite NEVPNManager.shared(), the
        // one system-wide personal-VPN slot. Re-add only once it is truly wired.
        XCTAssertFalse(AdapterFactory.availableRungs.contains(.ikev2),
                       "an unreachable rung must not be offered in the picker")
        XCTAssertEqual(AdapterFactory.availableRungs, AdapterFactory.implementedRungs)
    }
}

final class PresentationTests: XCTestCase {
    func p(_ state: TunnelState) -> Presentation {
        Presentation.make(state: state, serverName: "Stockholm", killSwitchArmed: true,
                          onDemandArmed: true, quality: .good)
    }

    func testFailureNeverLooksLikeSafeToBrowse() {
        for state: TunnelState in [.killSwitchActive, .error(.allRungsFailed), .reconnecting(attempt: 1),
                                   .reasserting, .error(.notConfigured), .error(.configurationInvalid)] {
            let pres = p(state)
            XCTAssertNotEqual(pres.tint, .good, "\(state) must not read as protected")
            XCTAssertNotEqual(pres.headline, "Protected")
        }
    }

    /// "Never set up" and "the signature failed" are both non-protected, but
    /// only one of them is an incident. Showing the alarming copy for a fresh
    /// install trains the user to ignore it when it matters.
    func testNotConfiguredReadsAsSetupNotAsAnAttack() {
        let fresh = p(.error(.notConfigured))
        XCTAssertEqual(fresh.tint, .neutral)
        XCTAssertFalse(fresh.headline.lowercased().contains("traffic blocked"))
        XCTAssertFalse(fresh.detail.lowercased().contains("could not be verified"))
        XCTAssertEqual(fresh.primaryAction, .openSettings)

        let tampered = p(.error(.configurationInvalid))
        XCTAssertEqual(tampered.tint, .danger)
        XCTAssertTrue(tampered.detail.lowercased().contains("could not be verified"))
    }

    func testReconnectingSaysTrafficIsBlockedNotLeaking() {
        XCTAssertTrue(p(.reconnecting(attempt: 1)).detail.lowercased().contains("paused"))
        XCTAssertTrue(p(.reconnecting(attempt: 1)).voiceOver.lowercased().contains("not leaking"))
    }

    func testConnectedShowsServerAndQuality() {
        let pres = p(.connected(rung: .wireGuardUDP, server: "s"))
        XCTAssertEqual(pres.tint, .good)
        XCTAssertEqual(pres.detail, "Stockholm")
        XCTAssertTrue(pres.showsQuality)
        XCTAssertEqual(pres.primaryAction, .disconnect)
    }

    func testDegradedStillReadsAsProtectedButWarned() {
        let pres = p(.degraded(rung: .wireGuardUDP, reason: .highLoss))
        XCTAssertEqual(pres.tint, .warning)
        XCTAssertTrue(pres.headline.hasPrefix("Protected"))
    }

    func testErrorsNameACauseAndAnAction() {
        let denied = p(.error(.systemDenied))
        XCTAssertEqual(denied.primaryAction, .openSettings)
        XCTAssertFalse(denied.detail.isEmpty)
        let config = p(.error(.configurationInvalid))
        XCTAssertTrue(config.detail.contains("signed configuration"))
    }

    func testQualityThresholds() {
        XCTAssertEqual(Presentation.Quality.from(rttMs: 30, lossFraction: 0), .good)
        XCTAssertEqual(Presentation.Quality.from(rttMs: 200, lossFraction: 0), .fair)
        XCTAssertEqual(Presentation.Quality.from(rttMs: 30, lossFraction: 0.05), .weak)
    }

    func testEveryStateHasNonEmptyCopy() {
        let states: [TunnelState] = [.disconnected, .onDemandArmed, .connecting(rung: .wireGuardUDP),
                                     .handshaking(rung: .wireGuardUDP),
                                     .connected(rung: .wireGuardUDP, server: "s"), .reasserting,
                                     .reconnecting(attempt: 1),
                                     .degraded(rung: .wireGuardUDP, reason: .highLoss),
                                     .killSwitchActive, .error(.internalFailure)]
        for s in states {
            let pres = p(s)
            XCTAssertFalse(pres.headline.isEmpty)
            XCTAssertFalse(pres.detail.isEmpty)
            XCTAssertFalse(pres.primaryActionTitle.isEmpty)
            XCTAssertFalse(pres.voiceOver.isEmpty)
        }
    }
}
