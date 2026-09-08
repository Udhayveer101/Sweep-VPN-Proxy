import XCTest
@testable import SweepVPNCore

/// `Server.load` carries weight 0.4 in the score and was only ever seeded from
/// the speed a relay *advertises*. These guard the measured replacement: that a
/// real observed rate moves it, that an unmeasured relay keeps its seed, and
/// that a fast relay actually outranks a slow one with identical latency —
/// which is the case connect-RTT probing cannot see and the user experiences as
/// "connected but slow".
final class RelayThroughputTests: XCTestCase {

    private func store() -> RelayThroughputStore {
        RelayThroughputStore(suiteName: "sweep.test.\(UUID().uuidString)")
    }

    private func relay(_ id: String, load: Double = 0.5) -> Server {
        var s = Server(id: id, name: id, countryCode: "JP", publicKey: "",
                       endpoints: [], dnsServers: [], ipv4Address: "")
        s.load = load
        return s
    }

    func testAnUnmeasuredRelayHasNoReading() {
        XCTAssertNil(store().normalized(for: "vpngate:1.2.3.4:443:tcp"))
    }

    func testAFastRelayNormalisesHigherThanASlowOne() {
        let s = store()
        s.record("fast", bytesPerSecond: 2_000_000)
        s.record("slow", bytesPerSecond: 40_000)
        XCTAssertGreaterThan(s.normalized(for: "fast")!, s.normalized(for: "slow")!)
    }

    func testTheReadingIsCappedAtOne() {
        let s = store()
        s.record("firehose", bytesPerSecond: 50_000_000)
        XCTAssertEqual(s.normalized(for: "firehose")!, 1, accuracy: 0.0001)
    }

    /// A relay that recovers has to be able to climb back, or one bad interval
    /// pins it at the bottom of the pool for good.
    func testTheAverageMovesTowardsTheNewestSample() {
        let s = store()
        s.record("r", bytesPerSecond: 50_000)
        let first = s.normalized(for: "r")!
        s.record("r", bytesPerSecond: 3_000_000)
        XCTAssertGreaterThan(s.normalized(for: "r")!, first)
    }

    func testNegativeAndNonFiniteRatesAreIgnored() {
        let s = store()
        s.record("r", bytesPerSecond: -1)
        s.record("r", bytesPerSecond: .infinity)
        s.record("r", bytesPerSecond: .nan)
        XCTAssertNil(s.normalized(for: "r"))
    }

    /// The seed is the right prior for a relay nobody has carried traffic on;
    /// overwriting it with a default would throw away the only signal we have.
    func testAppliedLeavesUnmeasuredRelaysOnTheirSeed() {
        let s = store()
        s.record("measured", bytesPerSecond: 2_000_000)
        let applied = s.applied(to: [relay("measured", load: 0.9), relay("untouched", load: 0.3)])
        XCTAssertEqual(applied.first { $0.id == "untouched" }!.load, 0.3, accuracy: 0.0001)
        XCTAssertLessThan(applied.first { $0.id == "measured" }!.load, 0.9)
    }

    func testAppliedIsANoOpWithNothingRecorded() {
        let applied = store().applied(to: [relay("a", load: 0.42)])
        XCTAssertEqual(applied[0].load, 0.42, accuracy: 0.0001)
    }

    /// The point of the whole thing: two relays that ping identically, one of
    /// which actually delivers bandwidth.
    func testTheScorePrefersTheRelayThatActuallyDeliveredBandwidth() {
        let s = store()
        s.record("fast", bytesPerSecond: 2_500_000)
        s.record("slow", bytesPerSecond: 30_000)
        let applied = s.applied(to: [relay("fast"), relay("slow")])
        let probe = ServerProbe(rttMs: 150, lossFraction: 0, jitterMs: 0)
        let scored = Dictionary(uniqueKeysWithValues:
            applied.map { ($0.id, ServerScoring.score($0, probe)) })
        XCTAssertLessThan(scored["fast"]!, scored["slow"]!)   // lower is better
    }

    /// A shared suite that grows without bound is a slow leak.
    func testTheStoreStaysBounded() {
        let s = store()
        for i in 0..<80 { s.record("relay\(i)", bytesPerSecond: Double(i + 1) * 10_000) }
        XCTAssertLessThanOrEqual(s.loadAll().count, 64)
        // The bound drops the weakest, so the fastest relay must survive it.
        XCTAssertNotNil(s.normalized(for: "relay79"))
    }
}
