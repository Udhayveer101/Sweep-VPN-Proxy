import XCTest
@testable import SweepVPNCore

/// The proximity prior must break ties without ever outranking measured speed.
/// If it can override RTT, the app will cheerfully pick a slow nearby server.
final class ProximityTests: XCTestCase {

    private func server(_ id: String, _ cc: String) -> Server {
        Server(id: id, name: id, countryCode: cc,
               publicKey: "k",
               endpoints: [ServerEndpoint(host: "203.0.113.1", port: 51820, rung: .wireGuardUDP)],
               dnsServers: ["10.0.0.1"],
               ipv4Address: "10.0.0.2")
    }
    private func probe(rtt: Double) -> ServerProbe {
        ServerProbe(rttMs: rtt, lossFraction: 0, jitterMs: 0)
    }

    func testOrdersRegionsOutwardFromIndia() {
        let ordered = ["IN", "SG", "JP", "DE", "US"]
        let penalties = ordered.map { ServerScoring.proximityPenalty($0) }
        XCTAssertEqual(penalties, penalties.sorted(),
                       "penalties must increase with distance from home: \(penalties)")
        XCTAssertEqual(ServerScoring.proximityPenalty("IN"), 0)
    }

    func testBreaksTiesTowardTheNearerRegion() {
        let candidates = [(server("nl", "NL"), probe(rtt: 120)),
                          (server("sg", "SG"), probe(rtt: 120))]
        XCTAssertEqual(ServerScoring.best(from: candidates, rung: .wireGuardUDP)?.id, "sg")
    }

    /// The load-bearing guarantee: a measurably faster far server still wins.
    func testNeverOutranksAGenuinelyFasterServer() {
        let candidates = [(server("nl", "NL"), probe(rtt: 100)),
                          (server("in", "IN"), probe(rtt: 115))]
        XCTAssertEqual(ServerScoring.best(from: candidates, rung: .wireGuardUDP)?.id, "nl",
                       "a 15 ms advantage must beat the proximity prior")
    }
}
