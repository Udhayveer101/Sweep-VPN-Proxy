import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// A relay that authenticates and then delivers a trickle is invisible to every
/// check the tunnel has: bytes *are* moving, so `sampleLiveness` calls it
/// healthy, no failure is ever reported, and the coordinator happily sits on it
/// forever. That is the state the user reports as "connected but the internet is
/// slow". These guard the handover that gets off it — and, just as importantly,
/// the guards that stop it turning the pool into a carousel.
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

    /// The whole point: two sub-floor samples, past the dwell, with somewhere
    /// better to go.
    func testASustainedTrickleHandsOverToAnotherRelay() {
        let (c, log, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"))

        // Well past `voluntarySwitchDwell`, so the relay has had its fair run.
        let later = Date().addingTimeInterval(120)
        c.noteThroughput(bytesPerSecond: 20_000, now: later)
        c.noteThroughput(bytesPerSecond: 20_000, now: later)

        let moved = XCTestExpectation(description: "handed over to the other relay")
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
            if c.activeServer?.id == ServerID("fast") { moved.fulfill() }
        }
        wait(for: [moved], timeout: 5)
        XCTAssertEqual(log.all.last, ServerID("fast"))
    }

    /// One quiet interval is the user not loading anything, not a bad relay.
    func testASingleSlowSampleIsNotEnough() {
        let (c, _, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        c.noteThroughput(bytesPerSecond: 20_000, now: Date().addingTimeInterval(120))
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"),
                       "one sample under the floor must not cost a handover")
    }

    /// A relay only just connected has not earned a verdict yet — the opening
    /// seconds of a session are slow for reasons that are not the relay's.
    func testATrickleBeforeTheDwellIsIgnored() {
        let (c, _, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        let soon = Date().addingTimeInterval(5)
        c.noteThroughput(bytesPerSecond: 20_000, now: soon)
        c.noteThroughput(bytesPerSecond: 20_000, now: soon)
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"))
    }

    /// A relay doing real work is left alone however long the session runs.
    func testAHealthyRateNeverTriggersAHandover() {
        let (c, _, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        let later = Date().addingTimeInterval(120)
        for _ in 0..<6 { c.noteThroughput(bytesPerSecond: 1_500_000, now: later) }
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(c.activeServer?.id, ServerID("slow"))
    }

    /// With one relay there is nowhere better to go, and dropping the tunnel to
    /// redial the same machine is strictly worse than a slow tunnel.
    func testASingleRelayIsNeverAbandonedForBeingSlow() {
        let log = DialLog()
        let up = expectation(description: "connected")
        up.assertForOverFulfill = false
        let c = coordinator(pool: [relay("only", load: 0.1)], dialled: log,
                            onAuthenticated: { _, _ in up.fulfill() })
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        let later = Date().addingTimeInterval(120)
        for _ in 0..<4 { c.noteThroughput(bytesPerSecond: 10_000, now: later) }
        Thread.sleep(forTimeInterval: 0.6)
        XCTAssertEqual(c.activeServer?.id, ServerID("only"))
        XCTAssertEqual(log.all, [ServerID("only")], "no redial of the only relay there is")
    }

    /// A uniformly slow network must not cycle the pool on every sample pair —
    /// each handover costs a reconnect, so unchecked it is worse than the slow
    /// relay it is running from.
    func testTheCooldownStopsThePoolBecomingACarousel() {
        let (c, log, up) = connectedPool()
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        let later = Date().addingTimeInterval(120)
        for _ in 0..<10 { c.noteThroughput(bytesPerSecond: 10_000, now: later) }
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertLessThanOrEqual(log.all.count, 2,
                                 "ten slow samples inside the cooldown is one handover, not five")
    }
}
