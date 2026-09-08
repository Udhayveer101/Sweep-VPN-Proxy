import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// The coordinator used to tear the tunnel down and re-cut the pool when the
/// measured rate sat under 2 Mbps for two samples. It could not work, and the
/// reason is worth keeping in a test rather than only in a commit message:
/// **passive byte counters cannot tell a slow relay from an unsaturated one.**
/// A game pushing 40 KB/s over a healthy relay produces exactly the numbers a
/// throttled relay does, so the check fired hardest on the low-bandwidth
/// sessions it was meant to protect — a hard teardown, with the tunnel down for
/// a whole OpenVPN handshake, every time the cooldown expired.
///
/// This guards the absence of that behaviour. Throughput is still measured; it
/// ranks relays at connect time, where comparing history is a fair question.
final class RelayThroughputHandoverTests: XCTestCase {

    private func relay(_ id: String, load: Double) -> Server {
        Server(id: ServerID(id), name: id, countryCode: "JP", publicKey: "",
               endpoints: [.init(host: id, port: 443, rung: .openVPNTCP)],
               dnsServers: ["8.8.8.8"], ipv4Address: "10.0.0.2",
               load: load, provider: "VPN Gate")
    }

    private func coordinator(pool: [Server], dialled: DialLog,
                             onAuthenticated: @escaping @Sendable (TunnelAdapter, Server) -> Void = { _, _ in })
    -> ConnectionCoordinator {
        var constants = AutoModeConstants()
        constants.raceStagger = 0.01
        constants.raceDeadline = 0.5
        constants.slowRungDeadline = 0.5
        let engine = AutoModeEngine(constants: constants,
                                    preference: .forced(.openVPNTCP),
                                    enabledRungs: [.openVPNTCP])
        return ConnectionCoordinator(
            engine: engine,
            catalog: ServerCatalog(servers: pool, rungs: [.openVPNTCP]),
            memory: NetworkMemory(),
            constants: constants,
            build: { rung, server in
                dialled.append(server.id)
                return FakeAdapter(rung: rung, behaviour: .authenticate(after: 0.02))
            },
            callbacks: .init(onAuthenticated: onAuthenticated,
                             onInbound: { _, _ in },
                             onExhausted: { _ in }))
    }

    final class DialLog: @unchecked Sendable {
        private var ids: [ServerID] = []
        private let lock = NSLock()
        func append(_ id: ServerID) { lock.lock(); ids.append(id); lock.unlock() }
        var all: [ServerID] { lock.lock(); defer { lock.unlock() }; return ids }
    }

    /// `load` orders an unmeasured pool, so "slow" is dialled first and is the
    /// one we then starve.
    private func connectedPool() -> (ConnectionCoordinator, DialLog, XCTestExpectation) {
        let pool = [relay("slow", load: 0.1), relay("fast", load: 0.2)]
        let log = DialLog()
        let up = expectation(description: "connected")
        // A handover authenticates again; the tests below wait on the *first*
        // connect and then assert on where the tunnel ended up.
        up.assertForOverFulfill = false
        let c = coordinator(pool: pool, dialled: log, onAuthenticated: { _, _ in up.fulfill() })
        return (c, log, up)
    }

    /// A sustained trickle is a fact about the *session*, not the relay, and
    /// must never cost the user their tunnel.
    func testASustainedTrickleNeverCostsTheTunnel() {
        let (c, log, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"))
        let dialsAtConnect = log.all.count

        // Far past every threshold the old check used: well beyond the dwell,
        // many consecutive samples, all of them deep under the old floor. This
        // is what a game looks like.
        let later = Date().addingTimeInterval(300)
        for _ in 0..<10 { c.noteThroughput(bytesPerSecond: 20_000, now: later) }

        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"),
                       "a low-bandwidth session must not be mistaken for a bad relay")
        XCTAssertEqual(log.all.count, dialsAtConnect,
                       "no relay may be dialled on throughput grounds")
    }

    /// A rate of literally zero — an idle user, or a leg that has already died —
    /// is the case that produced `relayTooSlow: 10 KB/s` seven seconds after
    /// `wssFailed` in the field log.
    func testAnIdleSessionNeverCostsTheTunnel() {
        let (c, log, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        let dialsAtConnect = log.all.count

        let later = Date().addingTimeInterval(300)
        for _ in 0..<10 { c.noteThroughput(bytesPerSecond: 0, now: later) }

        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"))
        XCTAssertEqual(log.all.count, dialsAtConnect)
    }
}
