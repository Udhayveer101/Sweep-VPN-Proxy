import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// OpenVPN 3 does not report a dead relay as a failure. It absorbs the drop
/// into its own reconnect loop and emits RECONNECTING, then grinds through
/// `connTimeout` (30s) before it gives up — which is the freeze the user sees,
/// with a fully authenticated standby relay sitting idle the whole time.
/// A reconnect *we* asked for is the one kind that must stay silent.
final class SelfReconnectTests: XCTestCase {

    private func adapter() -> OpenVPNTunnelAdapter {
        let endpoint = ServerEndpoint(host: "203.0.113.7", port: 443,
                                      rung: .openVPNTCP,
                                      openVPNProfile: "client\nremote 203.0.113.7 443 tcp\n")
        let server = Server(id: "relay", name: "relay", countryCode: "JP", publicKey: "",
                            endpoints: [endpoint], dnsServers: ["8.8.8.8"],
                            ipv4Address: "10.0.0.2", provider: "VPN Gate")
        return OpenVPNTunnelAdapter(rung: .openVPNTCP, server: server, endpoint: endpoint)!
    }

    func testARelayHangingUpIsReportedInsteadOfSilentlyRetried() {
        let a = adapter()
        let reported = expectation(description: "the coordinator hears about it")
        a.onFailure = { _ in reported.fulfill() }

        a.event("RECONNECTING", "")

        wait(for: [reported], timeout: 1)
    }

    func testAReconnectWeAskedForIsNotAFailure() {
        let a = adapter()
        let reported = expectation(description: "stays quiet")
        reported.isInverted = true
        a.onFailure = { _ in reported.fulfill() }

        a.reassert()                 // network change: we drove this one
        a.event("RECONNECTING", "")

        wait(for: [reported], timeout: 0.5)
    }
}
