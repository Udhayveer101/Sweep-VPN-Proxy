import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// A scriptable stand-in for a real rung: it either authenticates after a delay
/// or fails, so the whole fallback ladder can be exercised deterministically.
final class FakeAdapter: TunnelAdapter, @unchecked Sendable {
    enum Behaviour { case authenticate(after: TimeInterval), fail(after: TimeInterval), hang }

    let rung: ProtocolRung
    let behaviour: Behaviour
    private(set) var stopped = false
    private(set) var sentPackets: [Data] = []
    private var onInbound: (@Sendable ([Data], [NSNumber]) -> Void)?

    init(rung: ProtocolRung, behaviour: Behaviour) {
        self.rung = rung
        self.behaviour = behaviour
    }

    func start(onAuthenticated: @escaping @Sendable () -> Void,
               onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
               onFailure: @escaping @Sendable (TunnelErrorKind) -> Void) {
        self.onInbound = onInbound
        switch behaviour {
        case .authenticate(let delay):
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                guard !self.stopped else { return }
                onAuthenticated()
            }
        case .fail(let delay):
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                guard !self.stopped else { return }
                onFailure(.allRungsFailed)
            }
        case .hang:
            break
        }
    }

    func send(packets: [Data], protocols: [NSNumber]) { sentPackets += packets }
    func stop() { stopped = true }
    func reassert() {}
    var lastHandshakeAgeSeconds: Int64 { stopped ? -1 : 0 }
    var transferred: (tx: UInt64, rx: UInt64) { (0, 0) }
    func deliver(_ packet: Data) { onInbound?([packet], [NSNumber(value: AF_INET)]) }
}

final class ConnectionCoordinatorTests: XCTestCase {
    func server() -> Server {
        Server(id: "s", name: "Server", countryCode: "ZZ", publicKey: "pk",
               endpoints: ProtocolRung.allCases.map { .init(host: "127.0.0.1", port: 443, rung: $0) },
               dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")
    }

    func makeCoordinator(behaviours: [ProtocolRung: FakeAdapter.Behaviour],
                         preference: ProtocolPreference = .automatic,
                         memory: NetworkMemory = .init(),
                         onAuthenticated: @escaping @Sendable (TunnelAdapter, Server) -> Void = { _, _ in },
                         onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void = { _, _ in },
                         onExhausted: @escaping @Sendable (TunnelErrorKind) -> Void = { _ in })
    -> (ConnectionCoordinator, @Sendable (ProtocolRung) -> FakeAdapter?) {
        let box = AdapterBox()
        var constants = AutoModeConstants()
        constants.raceStagger = 0.02
        constants.raceDeadline = 1.0
        let engine = AutoModeEngine(constants: constants, preference: preference,
                                    enabledRungs: Set(ProtocolRung.allCases)
                                        .intersection(AdapterFactory.implementedRungs))
        let coordinator = ConnectionCoordinator(
            engine: engine,
            catalog: ServerCatalog(servers: [server()]),
            memory: memory,
            constants: constants,
            build: { rung, _ in
                guard let behaviour = behaviours[rung] else { throw AdapterFactoryError.rungNotImplemented(rung) }
                let adapter = FakeAdapter(rung: rung, behaviour: behaviour)
                box.store(adapter)
                return adapter
            },
            callbacks: .init(onAuthenticated: onAuthenticated, onInbound: onInbound,
                             onExhausted: onExhausted))
        return (coordinator, { box.adapter(for: $0) })
    }

    /// Thread-safe holder for a value captured by an adapter callback.
    final class Winner: @unchecked Sendable {
        private var value: ProtocolRung?
        private let lock = NSLock()
        var rung: ProtocolRung? { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ r: ProtocolRung) { lock.lock(); value = r; lock.unlock() }
    }

    final class AdapterBox: @unchecked Sendable {
        private var adapters: [ProtocolRung: FakeAdapter] = [:]
        private let lock = NSLock()
        func store(_ a: FakeAdapter) { lock.lock(); adapters[a.rung] = a; lock.unlock() }
        func adapter(for rung: ProtocolRung) -> FakeAdapter? {
            lock.lock(); defer { lock.unlock() }; return adapters[rung]
        }
    }

    func testFastestAuthenticatingRungWinsAndLosersAreStopped() {
        let won = XCTestExpectation(description: "a rung won")
        let winner = Winner()
        let (coordinator, adapter) = makeCoordinator(
            behaviours: [.wireGuardUDP: .hang,
                         .wireGuardQUIC: .hang,
                         .wireGuardTLS: .authenticate(after: 0.05)],
            onAuthenticated: { a, _ in winner.set(a.rung); won.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 5)
        XCTAssertEqual(winner.rung, .wireGuardTLS)
        XCTAssertEqual(coordinator.activeRung, .wireGuardTLS)
        XCTAssertTrue(adapter(.wireGuardUDP)?.stopped ?? false, "losing rungs must be torn down")
    }

    func testConnectingIsNotEnough_onlyAuthenticationCommits() {
        // Every rung connects but none authenticates: the coordinator must end
        // exhausted (traffic stays blocked), never "connected".
        let exhausted = XCTestExpectation(description: "gave up")
        let (coordinator, _) = makeCoordinator(
            behaviours: Dictionary(uniqueKeysWithValues: AdapterFactory.implementedRungs.map { ($0, .hang) }),
            onExhausted: { _ in exhausted.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [exhausted], timeout: 20)
        XCTAssertNil(coordinator.activeRung)
    }

    func testLadderWalksDownToAWorkingRung() {
        let won = XCTestExpectation(description: "fell through to TCP")
        let winner = Winner()
        var behaviours: [ProtocolRung: FakeAdapter.Behaviour] = [:]
        for rung in AdapterFactory.implementedRungs {
            behaviours[rung] = rung == .wireGuardTCP ? .authenticate(after: 0.05) : .fail(after: 0.05)
        }
        let (coordinator, _) = makeCoordinator(behaviours: behaviours,
                                               onAuthenticated: { a, _ in winner.set(a.rung); won.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 20)
        XCTAssertEqual(winner.rung, .wireGuardTCP)
    }

    func testUDPBlockedNetworkIsRememberedAfterTheUDPRungsDie() {
        let won = XCTestExpectation(description: "connected over a stream rung")
        var behaviours: [ProtocolRung: FakeAdapter.Behaviour] = [:]
        for rung in AdapterFactory.implementedRungs {
            behaviours[rung] = rung.isUDP ? .fail(after: 0.05) : .authenticate(after: 0.05)
        }
        let (coordinator, _) = makeCoordinator(behaviours: behaviours,
                                               onAuthenticated: { _, _ in won.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 20)
        XCTAssertTrue(coordinator.updatedMemory.isUDPBlocked(now: Date()),
                      "the next connect here must skip UDP")
        XCTAssertEqual(coordinator.updatedMemory.lastGoodRung, coordinator.activeRung)
    }

    func testRememberedRungConnectsWithoutRacing() {
        let won = XCTestExpectation(description: "connected")
        var memory = NetworkMemory()
        memory.noteSuccess(rung: .wireGuardTLS, now: Date())
        let winner = Winner()
        let (coordinator, adapter) = makeCoordinator(
            behaviours: [.wireGuardUDP: .authenticate(after: 0.01),
                         .wireGuardTLS: .authenticate(after: 0.05)],
            memory: memory,
            onAuthenticated: { a, _ in winner.set(a.rung); won.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 5)
        XCTAssertEqual(winner.rung, .wireGuardTLS, "a known-good rung is used directly")
        XCTAssertNil(adapter(.wireGuardUDP), "no race should have been started")
    }

    func testForcedPreferenceNeverFallsBackToAnotherRung() {
        let exhausted = XCTestExpectation(description: "failed closed on the forced rung")
        let (coordinator, adapter) = makeCoordinator(
            behaviours: [.wireGuardQUIC: .fail(after: 0.05),
                         .wireGuardTLS: .authenticate(after: 0.05)],
            preference: .forced(.wireGuardQUIC),
            onExhausted: { _ in exhausted.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [exhausted], timeout: 10)
        XCTAssertNil(adapter(.wireGuardTLS), "an override must not be silently overridden")
        XCTAssertNil(coordinator.activeRung)
    }

    func testPacketsOnlyFlowThroughTheCommittedRung() {
        let won = XCTestExpectation(description: "won")
        let (coordinator, adapter) = makeCoordinator(
            behaviours: [.wireGuardUDP: .authenticate(after: 0.05), .wireGuardTLS: .hang],
            onAuthenticated: { _, _ in won.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 5)
        coordinator.send(packets: [Data([1, 2, 3])], protocols: [NSNumber(value: AF_INET)])
        XCTAssertEqual(adapter(.wireGuardUDP)?.sentPackets.count, 1)
        XCTAssertEqual(adapter(.wireGuardTLS)?.sentPackets.count ?? 0, 0)
    }

    func testInboundFromALosingRungIsIgnored() {
        let won = XCTestExpectation(description: "won")
        let delivered = XCTestExpectation(description: "inbound delivered")
        delivered.isInverted = true
        let (coordinator, adapter) = makeCoordinator(
            behaviours: [.wireGuardUDP: .authenticate(after: 0.05), .wireGuardTLS: .hang],
            onAuthenticated: { _, _ in won.fulfill() },
            onInbound: { _, _ in delivered.fulfill() })
        coordinator.start(signals: .init())
        wait(for: [won], timeout: 5)
        adapter(.wireGuardTLS)?.deliver(Data([9]))
        wait(for: [delivered], timeout: 1)
    }
}
