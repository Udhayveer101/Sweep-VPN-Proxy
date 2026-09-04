import XCTest
@testable import SweepVPNCore

/// `Server.reliability` carried weight 0.6 in the score from the beginning and
/// nothing ever wrote it. These guard the two things that make it mean
/// something: that a measured lifetime moves it, and that a relay which has
/// held a long session outranks one that keeps dropping.
final class RelayStabilityTests: XCTestCase {

    private func store() -> RelayStabilityStore {
        RelayStabilityStore(suiteName: "sweep.test.\(UUID().uuidString)")
    }

    func testAnUnmeasuredRelayStaysOptimistic() {
        XCTAssertEqual(store().reliability(for: "vpngate:1.2.3.4:443:tcp"), 1)
    }

    func testALongSessionOutranksARelayThatKeepsDropping() {
        let s = store()
        s.record("steady", lasted: 600)
        s.record("flaky", lasted: 8)
        XCTAssertGreaterThan(s.reliability(for: "steady"), s.reliability(for: "flaky"))
        XCTAssertEqual(s.reliability(for: "steady"), 1, accuracy: 0.001)   // capped
    }

    /// The rolling average has to actually move, or a relay that recovers is
    /// stuck at the bottom of the pool for good.
    func testTheAverageMovesTowardsTheNewestSample() {
        let s = store()
        s.record("r", lasted: 10)
        let first = s.reliability(for: "r")
        s.record("r", lasted: 300)
        XCTAssertGreaterThan(s.reliability(for: "r"), first)
    }

    func testTheScoreActuallyPrefersTheStableRelay() {
        let s = store()
        s.record("flaky", lasted: 5)
        let base = Server(id: "flaky", name: "flaky", countryCode: "JP", publicKey: "",
                          endpoints: [], dnsServers: [], ipv4Address: "")
        let steady = Server(id: "steady", name: "steady", countryCode: "JP", publicKey: "",
                            endpoints: [], dnsServers: [], ipv4Address: "")
        let applied = s.applied(to: [base, steady])
        let probe = ServerProbe(rttMs: 100, lossFraction: 0, jitterMs: 0)
        let scored = applied.map { ($0.id, ServerScoring.score($0, probe)) }
        let flaky = scored.first { $0.0 == "flaky" }!.1
        let good = scored.first { $0.0 == "steady" }!.1
        XCTAssertLessThan(good, flaky)   // lower is better
    }
}
