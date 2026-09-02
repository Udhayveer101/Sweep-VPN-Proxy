import XCTest
@testable import SweepVPNCore

/// A relay's PUSH_REPLY decides this device's address, routes and resolvers.
/// It is the one place in the app where a machine we do not run gets to shape
/// the network stack, so it is validated rather than trusted.
final class PushedTunnelSettingsTests: XCTestCase {

    /// The exact payload a live VPN Gate relay pushed, captured from the shim.
    private let realPush = """
    {"mtu":0,"remote":"61.6.43.75","sessionName":"61.6.43.75",
     "redirectGatewayV4":true,"redirectGatewayV6":false,
     "addresses":[{"address":"10.211.1.13","prefix":30,"gateway":"10.211.1.14","ipv6":false}],
     "routes":[],"dns":["10.211.254.254","8.8.8.8"]}
    """

    private func decode(_ json: String) throws -> PushedTunnelSettings {
        try JSONDecoder().decode(PushedTunnelSettings.self, from: Data(json.utf8))
    }

    func testDecodesWhatARealRelayActuallySent() throws {
        let p = try decode(realPush)
        XCTAssertEqual(p.ipv4Address?.address, "10.211.1.13")
        XCTAssertEqual(p.ipv4Address?.prefix, 30)
        XCTAssertEqual(p.ipv4Address?.gateway, "10.211.1.14")
        XCTAssertEqual(p.dns, ["10.211.254.254", "8.8.8.8"])
        XCTAssertTrue(p.redirectGatewayV4)
        XCTAssertTrue(p.hasUsableAddress)
        XCTAssertNoThrow(try p.validated())
    }

    /// VPN Gate pushes mtu 0. Installing that would produce an interface that
    /// cannot carry a packet.
    func testZeroMTUFallsBackToSomethingUsable() throws {
        let p = try decode(realPush)
        XCTAssertEqual(p.mtu, 0)
        XCTAssertEqual(p.effectiveMTU, 1400)
        XCTAssertEqual(try p.validated().mtu, 1400)
    }

    func testAbsurdMTUIsClamped() {
        XCTAssertEqual(PushedTunnelSettings(mtu: 70000).effectiveMTU, 1400)
        XCTAssertEqual(PushedTunnelSettings(mtu: 40).effectiveMTU, 1400)
        XCTAssertEqual(PushedTunnelSettings(mtu: 1400).effectiveMTU, 1400)
        XCTAssertEqual(PushedTunnelSettings(mtu: 1500).effectiveMTU, 1500)
    }

    func testAPushWithNoAddressIsRejected() {
        let p = PushedTunnelSettings(dns: ["1.1.1.1"])
        XCTAssertFalse(p.hasUsableAddress)
        XCTAssertThrowsError(try p.validated()) {
            XCTAssertEqual($0 as? PushedTunnelSettings.Rejection, .noAddress)
        }
    }

    func testAMalformedAddressIsRejectedRatherThanPassedToTheOS() {
        let bad = PushedTunnelSettings(addresses: [
            .init(address: "not-an-ip", prefix: 24, gateway: "10.0.0.1", ipv6: false)
        ])
        XCTAssertThrowsError(try bad.validated()) {
            XCTAssertEqual($0 as? PushedTunnelSettings.Rejection,
                           .malformedAddress("not-an-ip"))
        }
    }

    func testAnOutOfRangePrefixIsRejected() {
        let bad = PushedTunnelSettings(addresses: [
            .init(address: "10.0.0.2", prefix: 99, gateway: "10.0.0.1", ipv6: false)
        ])
        XCTAssertThrowsError(try bad.validated()) {
            XCTAssertEqual($0 as? PushedTunnelSettings.Rejection,
                           .badPrefix("10.0.0.2", 99))
        }
    }

    /// A relay that pushes junk among its resolvers must not get that junk into
    /// the network settings — but a valid entry alongside it still stands.
    func testGarbageResolversAreDroppedNotAccepted() throws {
        var p = try decode(realPush)
        p.dns = ["10.211.254.254", "", "not-an-ip", "8.8.8.8", "300.1.1.1"]
        XCTAssertEqual(try p.validated().dns, ["10.211.254.254", "8.8.8.8"])
    }

    func testGarbageRoutesAreDropped() throws {
        var p = try decode(realPush)
        p.routes = [
            .init(address: "10.0.0.0", prefix: 8, ipv6: false, exclude: false),
            .init(address: "junk", prefix: 8, ipv6: false, exclude: false),
            .init(address: "192.168.0.0", prefix: 77, ipv6: false, exclude: false),
        ]
        XCTAssertEqual(try p.validated().routes.map(\.address), ["10.0.0.0"])
    }

    // MARK: - How the plan is built from a push

    func testRedirectGatewayBecomesADefaultRoute() throws {
        let p = try decode(realPush)
        let policy = SecurityPolicy()
        let server = Server(id: "r", name: "relay", countryCode: "MY", publicKey: "",
                            endpoints: [], dnsServers: [], ipv4Address: "")
        let endpoint = ServerEndpoint(host: "61.6.43.75", port: 1998, rung: .openVPNTCP)

        let plan = policy.connectedPlan(server: server, endpoint: endpoint,
                                        pushed: try p.validated())
        XCTAssertEqual(plan.ipv4Address, "10.211.1.13")
        XCTAssertEqual(plan.ipv4Routes.count, 1)
        XCTAssertEqual(plan.dnsServers, ["10.211.254.254", "8.8.8.8"])
        XCTAssertEqual(plan.mtu, 1400)
        XCTAssertTrue(plan.forwardingEnabled)
    }

    /// VPN Gate relays are IPv4-only. Without blackholing v6 every
    /// AAAA-reachable site would leave over the physical interface while the
    /// UI claimed the tunnel was up.
    func testIPv6IsBlackholedWhenTheRelayOffersNone() throws {
        let p = try decode(realPush)
        var options = SecurityPolicyOptions()
        options.blockIPv6WhenUnavailable = true
        let policy = SecurityPolicy(options: options)
        let server = Server(id: "r", name: "relay", countryCode: "MY", publicKey: "",
                            endpoints: [], dnsServers: [], ipv4Address: "")
        let endpoint = ServerEndpoint(host: "61.6.43.75", port: 1998, rung: .openVPNTCP)

        let plan = policy.connectedPlan(server: server, endpoint: endpoint,
                                        pushed: try p.validated())
        XCTAssertNil(plan.ipv6Address)
        XCTAssertTrue(plan.ipv6Blocked)
        XCTAssertEqual(plan.ipv6Routes.count, 1, "v6 must be routed into the tunnel to be dropped")
    }

    /// Without redirect-gateway the relay gets exactly the routes it asked for
    /// and nothing wider.
    func testWithoutRedirectGatewayOnlyPushedRoutesAreInstalled() throws {
        var p = try decode(realPush)
        p.redirectGatewayV4 = false
        p.routes = [.init(address: "10.5.0.0", prefix: 16, ipv6: false, exclude: false)]

        let policy = SecurityPolicy()
        let server = Server(id: "r", name: "relay", countryCode: "MY", publicKey: "",
                            endpoints: [], dnsServers: [], ipv4Address: "")
        let endpoint = ServerEndpoint(host: "61.6.43.75", port: 1998, rung: .openVPNTCP)

        let plan = policy.connectedPlan(server: server, endpoint: endpoint,
                                        pushed: try p.validated())
        XCTAssertEqual(plan.ipv4Routes.count, 1)
        XCTAssertNotEqual(plan.ipv4Routes.first?.prefix, 0,
                          "a relay that did not ask for the default route must not get it")
    }
}
