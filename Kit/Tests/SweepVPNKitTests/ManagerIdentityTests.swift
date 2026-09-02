import XCTest
import NetworkExtension
@testable import SweepVPNKit

/// This Mac carries five unrelated VPN profiles (SkyVPN, X-VPN, Psiphon,
/// Betternet, Hotspot Shield). `loadAllFromPreferences()` returns all of them,
/// and the old code took `.first` — which is how an unrelated tunnel came to be
/// rendered as Sweep's own, and how install() could have overwritten it.
final class ManagerIdentityTests: XCTestCase {

    private func manager(providerID: String?) -> NETunnelProviderManager {
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerID
        proto.serverAddress = "test"
        m.protocolConfiguration = proto
        return m
    }

    func testIgnoresForeignProfilesListedFirst() {
        let foreign = ["com.skyvpn.app", "com.mac.xvpn", "ca.psiphon.Psiphon"].map(manager(providerID:))
        let mine = manager(providerID: "com.sweep.vpn.mac.tunnel")
        let selected = VPNConfigurator.selectOurs(from: foreign + [mine],
                                                  bundleIdentifier: "com.sweep.vpn.mac.tunnel")
        XCTAssertNotNil(selected)
        XCTAssertEqual((selected?.protocolConfiguration as? NETunnelProviderProtocol)?
                        .providerBundleIdentifier, "com.sweep.vpn.mac.tunnel")
    }

    /// The case that actually bit: no Sweep profile at all, several foreign ones.
    /// Must be nil so the UI says "not set up", not another VPN's status.
    func testReturnsNilWhenOnlyForeignProfilesExist() {
        let foreign = ["com.skyvpn.app", "com.mac.xvpn", "com.betternet.macos"].map(manager(providerID:))
        XCTAssertNil(VPNConfigurator.selectOurs(from: foreign,
                                                bundleIdentifier: "com.sweep.vpn.mac.tunnel"))
    }

    func testIgnoresProfilesWithNoProviderIdentifier() {
        XCTAssertNil(VPNConfigurator.selectOurs(from: [manager(providerID: nil)],
                                                bundleIdentifier: "com.sweep.vpn.mac.tunnel"))
    }
}
