import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// The failure this guards is the one from the field log: a pinned VPN Gate
/// relay carried the tunnel for ~60 s, dropped, and the coordinator redialled
/// *the same relay* on the same rung — which VPN Gate answers with AUTH_FAILED
/// — and then failed closed. With one relay stored there was nowhere else to
/// go, so every relay drop ended the session permanently.
///
/// Measured against the live relay list while fixing this: of three relays
/// dialled through the Worker, one never connected at all and one dropped at
/// ~92 s, while the third carried traffic for the whole run. A pool is not an
/// optimisation here — it is the difference between a tunnel that lasts an
/// hour and one that lasts a minute.
final class RelayHandoverTests: XCTestCase {

    private func relay(_ id: String) -> Server {
        Server(id: ServerID(id), name: id, countryCode: "JP", publicKey: "",
               endpoints: [.init(host: id, port: 443, rung: .openVPNTCP)],
               dnsServers: ["8.8.8.8"], ipv4Address: "10.0.0.2",
               provider: "VPN Gate")
    }

    /// Builds a coordinator forced onto OpenVPN/TCP over a pool of relays,
    /// where `behaviour` decides what each relay's adapter does.
    private func coordinator(pool: [Server],
                             behaviour: @escaping @Sendable (Server) -> FakeAdapter.Behaviour,
                             dialled: DialLog,
                             onAuthenticated: @escaping @Sendable (TunnelAdapter, Server) -> Void = { _, _ in },
                             onExhausted: @escaping @Sendable (TunnelErrorKind) -> Void = { _ in })
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
                return FakeAdapter(rung: rung, behaviour: behaviour(server))
            },
            callbacks: .init(onAuthenticated: onAuthenticated,
                             onInbound: { _, _ in },
                             onExhausted: onExhausted))
    }

    final class DialLog: @unchecked Sendable {
        private var ids: [ServerID] = []
        private let lock = NSLock()
        func append(_ id: ServerID) { lock.lock(); ids.append(id); lock.unlock() }
        var all: [ServerID] { lock.lock(); defer { lock.unlock() }; return ids }
    }

    /// A relay that drops a *live* tunnel must hand over to the next relay,
    /// never redial the one that just dropped.
    func testLiveDropHandsOverToTheNextRelay() {
        let pool = [relay("dead"), relay("good")]
        let log = DialLog()
        let connected = expectation(description: "the second relay carries the tunnel")
        connected.expectedFulfillmentCount = 2      // the drop, then the handover
        let c = coordinator(
            pool: pool,
            behaviour: { $0.id == ServerID("dead")
                ? .authenticateThenDrop(after: 0.02, dropAfter: 0.05)
                : .authenticate(after: 0.02) },
            dialled: log,
            onAuthenticated: { _, _ in connected.fulfill() })
        c.start(signals: NetworkSignals())
        wait(for: [connected], timeout: 5)
        XCTAssertEqual(c.activeServer?.id, ServerID("good"),
                       "the tunnel must end up on a relay that did not just drop it")
        XCTAssertEqual(Array(log.all.prefix(2)), ["dead", "good"],
                       "the dropped relay must not be redialled before the pool is spent")
    }

    /// A relay that never authenticates is burned too, so the handshake
    /// deadline moves down the pool instead of retrying the same dead host.
    func testStalledRelayIsBurnedAndTheNextIsTried() {
        let pool = [relay("hangs"), relay("good")]
        let log = DialLog()
        let up = expectation(description: "connected on the second relay")
        let c = coordinator(
            pool: pool,
            behaviour: { $0.id == ServerID("hangs") ? .hang : .authenticate(after: 0.02) },
            dialled: log,
            onAuthenticated: { _, _ in up.fulfill() })
        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        XCTAssertEqual(c.activeServer?.id, ServerID("good"))
    }

    /// The pool is swept a bounded number of times: a network where nothing
    /// works still fails closed rather than spinning on dead relays forever.
    func testAPoolThatNeverWorksStillFailsClosed() {
        let pool = [relay("a"), relay("b")]
        let log = DialLog()
        let gaveUp = expectation(description: "failed closed")
        let c = coordinator(
            pool: pool,
            behaviour: { _ in .fail(after: 0.01) },
            dialled: log,
            onExhausted: { _ in gaveUp.fulfill() })
        c.start(signals: NetworkSignals())
        wait(for: [gaveUp], timeout: 10)
        XCTAssertGreaterThan(log.all.count, 2, "every relay in the pool must be tried")
    }
}
