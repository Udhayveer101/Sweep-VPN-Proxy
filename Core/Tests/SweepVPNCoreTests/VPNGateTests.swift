import XCTest
@testable import SweepVPNCore

/// Parses a real capture of the VPN Gate public list, not a hand-written
/// fixture. The format is third-party and undocumented beyond the header row,
/// so the only meaningful test is against bytes VPN Gate actually served.
final class VPNGateTests: XCTestCase {

    private func loadCSV() throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "Fixtures/vpngate-sample",
                                                  withExtension: "csv"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testParsesEveryRelayInTheCapture() throws {
        let relays = VPNGate.parseCSV(try loadCSV())
        // 96 data rows in the capture; every one carries a decodable profile.
        XCTAssertEqual(relays.count, 96)
        XCTAssertTrue(relays.allSatisfy { !$0.ip.isEmpty })
        XCTAssertTrue(relays.allSatisfy { $0.port > 0 })
        XCTAssertTrue(relays.allSatisfy { $0.openVPNProfile.contains("<ca>") })
    }

    func testReadsTransportAndPortFromTheProfileNotTheCSV() throws {
        let relays = VPNGate.parseCSV(try loadCSV())
        let jp = try XCTUnwrap(relays.first { $0.ip == "219.100.37.224" })
        XCTAssertEqual(jp.proto, .tcp)
        XCTAssertEqual(jp.port, 443)
        XCTAssertEqual(jp.countryCode, "JP")
        XCTAssertEqual(jp.proto.rung, .openVPNTCP)
    }

    func testProfileParserHandlesPortOnTheRemoteLine() {
        let udp = VPNGate.parseProfile("""
        client
        proto udp
        remote 1.2.3.4 1195
        """)
        XCTAssertEqual(udp?.proto, .udp)
        XCTAssertEqual(udp?.port, 1195)

        // A trailing proto on `remote` wins, as OpenVPN itself treats it.
        let overridden = VPNGate.parseProfile("proto udp\nremote 1.2.3.4 443 tcp")
        XCTAssertEqual(overridden?.proto, .tcp)

        // No remote line at all is not a usable relay.
        XCTAssertNil(VPNGate.parseProfile("client\nproto udp"))
    }

    func testMalformedRowsAreSkippedRatherThanFailingTheBatch() {
        let csv = """
        *vpn_servers
        #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
        broken,,0,0,0,Nowhere,ZZ,0,0,0,0,no,nobody,,notbase64
        good,9.9.9.9,1,5,100,Japan,JP,1,1,1,1,2weeks,someone,,\(Data("proto udp\nremote 9.9.9.9 1194".utf8).base64EncodedString())
        *
        """
        let relays = VPNGate.parseCSV(csv)
        XCTAssertEqual(relays.map(\.ip), ["9.9.9.9"])
        XCTAssertEqual(relays.first?.logType, "2weeks")
    }

    // MARK: - Mapping into the catalog

    func testRelaysBecomeOpenVPNServersCarryingTheirProfile() throws {
        let servers = VPNGate.servers(fromCSV: try loadCSV())
        XCTAssertEqual(servers.count, 96)

        let s = try XCTUnwrap(servers.first { $0.id == "vpngate:219.100.37.224:443:tcp" })
        XCTAssertEqual(s.endpoints.count, 1)
        XCTAssertEqual(s.endpoints[0].rung, .openVPNTCP)
        XCTAssertNotNil(s.endpoints[0].openVPNProfile)
        XCTAssertTrue(s.isThirdPartyRelay)
        // Nothing about an OpenVPN relay is a WireGuard peer of ours.
        XCTAssertTrue(s.publicKey.isEmpty)
        XCTAssertFalse(s.requiresAccount)
    }

    func testOperatorLogClaimSurvivesIntoTheCatalog() throws {
        let servers = VPNGate.servers(fromCSV: try loadCSV())
        // The capture is full of relays that openly admit to retention; the
        // list must carry that through rather than drop it.
        XCTAssertTrue(servers.contains { ($0.logPolicy?.isEmpty == false) })
    }

    func testHostileJurisdictionsArePenalisedButNotBlocked() {
        XCTAssertGreaterThan(VPNGate.jurisdictionPenalty("RU"), 0)
        XCTAssertEqual(VPNGate.jurisdictionPenalty("JP"), 0)
        XCTAssertTrue(VPNGate.jurisdictionPenalty("RU").isFinite,
                      "a penalty gates ranking; .infinity would hide the server entirely")
    }

    // MARK: - The trust boundary

    func testAutomaticNeverSelectsAThirdPartyRelay() {
        let all = Set(ProtocolRung.allCases)
        let automatic = ProtocolPreference.automatic.permittedRungs(enabledTiers: all)
        XCTAssertFalse(automatic.contains(.openVPNUDP))
        XCTAssertFalse(automatic.contains(.openVPNTCP))
        XCTAssertTrue(automatic.allSatisfy(\.isOwnWireGuardTunnel))

        // It is reachable, but only by asking for it by name.
        let forced = ProtocolPreference.forced(.openVPNTCP).permittedRungs(enabledTiers: all)
        XCTAssertEqual(forced, [.openVPNTCP])
    }

    func testRelaysAreRankedWhenTheirRungIsInScope() throws {
        let servers = VPNGate.servers(fromCSV: try loadCSV())
        var wgOnly = ServerCatalog(servers: servers, rung: .wireGuardUDP)
        wgOnly.record(.init(rttMs: 10, lossFraction: 0), for: servers[0].id)
        XCTAssertTrue(wgOnly.ranked().isEmpty,
                      "an OpenVPN relay must not appear while only WireGuard is in scope")

        var withOVPN = ServerCatalog(servers: servers,
                                     rungs: [.wireGuardUDP, .openVPNTCP, .openVPNUDP])
        withOVPN.record(.init(rttMs: 10, lossFraction: 0), for: servers[0].id)
        XCTAssertEqual(withOVPN.ranked().count, servers.count)
        XCTAssertEqual(withOVPN.fastest()?.id, servers[0].id,
                       "the one measured relay outranks every unmeasured one")
    }

    func testUnmeasuredRelaysOrderByAdvertisedSpeed() {
        func relay(_ ip: String, speed: Double) -> Server {
            VPNGate.servers(from: [
                .init(hostName: ip, ip: ip, countryCode: "JP", countryName: "Japan",
                      advertisedPingMs: nil, speedBps: speed, sessions: nil,
                      logType: nil, operatorName: nil,
                      openVPNProfile: "remote \(ip) 443\nproto tcp",
                      proto: .tcp, port: 443)
            ])[0]
        }
        let catalog = ServerCatalog(servers: [relay("1.1.1.1", speed: 1_000_000),
                                              relay("2.2.2.2", speed: 900_000_000)],
                                    rungs: [.openVPNTCP])
        XCTAssertEqual(catalog.ranked().map(\.0.id).first, "vpngate:2.2.2.2:443:tcp",
                       "the fatter advertised line sorts first until we measure")
    }
}
