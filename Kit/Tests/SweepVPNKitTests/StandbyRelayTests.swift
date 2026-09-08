import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// The field log (`run C6A92AE5`) showed the shape this file exists to prevent:
///
///     +101.5s  wssEnded  relay ? dropped the session (close 1000 eof) after 24s
///              ...36 seconds of nothing at all...
///     +134.4s  ovpn      RECONNECTING
///
/// A third-party relay hanging up is not an exception on this rung, it is the
/// normal course of a session — VPN Gate volunteers FIN at 62 s idle, 92 s live
/// by the transport's own measurement. Dialling the replacement only *after*
/// the drop costs a whole OpenVPN handshake, so the user sees the tunnel die
/// roughly once a minute. Warming the next relay before the drop turns that
/// into a swap.
final class StandbyRelayTests: XCTestCase {

    private func relay(_ id: String, load: Double) -> Server {
        Server(id: ServerID(id), name: id, countryCode: "JP", publicKey: "",
               endpoints: [.init(host: id, port: 443, rung: .openVPNTCP)],
               dnsServers: ["8.8.8.8"], ipv4Address: "10.0.0.2",
               load: load, provider: "VPN Gate")
    }

    private final class Log: @unchecked Sendable {
        private var dials: [ServerID] = []
        private var events: [String] = []
        private let lock = NSLock()
        func dial(_ id: ServerID) { lock.lock(); dials.append(id); lock.unlock() }
        func event(_ name: String) { lock.lock(); events.append(name); lock.unlock() }
        var allDials: [ServerID] { lock.lock(); defer { lock.unlock() }; return dials }
        var allEvents: [String] { lock.lock(); defer { lock.unlock() }; return events }
    }

    /// `load` orders an unmeasured pool, so "first" is dialled first.
    private func constants() -> AutoModeConstants {
        var c = AutoModeConstants()
        c.raceStagger = 0.01
        c.raceDeadline = 0.5
        c.slowRungDeadline = 0.5
        // The real value is 40 s; the behaviour is identical, only sooner.
        c.standbyLeadTime = 0.2
        return c
    }

    /// A relay is warmed alongside the live one, without being handed any
    /// traffic and without disturbing the tunnel in place.
    func testAReplacementRelayIsWarmedBeforeAnythingGoesWrong() {
        let pool = [relay("first", load: 0.1), relay("second", load: 0.2)]
        let log = Log()
        let k = constants()
        let up = expectation(description: "connected")
        up.assertForOverFulfill = false

        let c = ConnectionCoordinator(
            engine: AutoModeEngine(constants: k, preference: .forced(.openVPNTCP),
                                   enabledRungs: [.openVPNTCP]),
            catalog: ServerCatalog(servers: pool, rungs: [.openVPNTCP]),
            memory: NetworkMemory(),
            constants: k,
            build: { rung, server in
                log.dial(server.id)
                return FakeAdapter(rung: rung, behaviour: .authenticate(after: 0.02))
            },
            callbacks: .init(onAuthenticated: { _, _ in up.fulfill() },
                             onInbound: { _, _ in },
                             onExhausted: { _ in },
                             onEvent: { name, _ in log.event(name) }))

        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        XCTAssertEqual(c.activeServer?.id, ServerID("first"))

        Thread.sleep(forTimeInterval: 1.0)
        XCTAssertEqual(log.allDials, [ServerID("first"), ServerID("second")],
                       "the second relay should have been warmed alongside the first")
        XCTAssertTrue(log.allEvents.contains("standbyReady"))
        // Warming must not disturb the tunnel that is working.
        XCTAssertEqual(c.activeServer?.id, ServerID("first"),
                       "arming a standby must not move the live tunnel")
    }

    /// The point of the whole exercise: when the live relay hangs up, the
    /// tunnel moves to the warmed one without dialling anything, and without
    /// ever reporting itself down.
    func testALiveDropIsAbsorbedByTheStandbyWithoutANewHandshake() {
        let pool = [relay("first", load: 0.1), relay("second", load: 0.2)]
        let log = Log()
        let k = constants()
        let connected = expectation(description: "connected")
        connected.assertForOverFulfill = false

        let c = ConnectionCoordinator(
            engine: AutoModeEngine(constants: k, preference: .forced(.openVPNTCP),
                                   enabledRungs: [.openVPNTCP]),
            catalog: ServerCatalog(servers: pool, rungs: [.openVPNTCP]),
            memory: NetworkMemory(),
            constants: k,
            build: { rung, server in
                log.dial(server.id)
                // The relay that wins drops the way VPN Gate does: it carries
                // the tunnel, then hangs up. The standby simply comes up.
                let behaviour: FakeAdapter.Behaviour = server.id == ServerID("first")
                    ? .authenticateThenDrop(after: 0.02, dropAfter: 0.6)
                    : .authenticate(after: 0.02)
                return FakeAdapter(rung: rung, behaviour: behaviour)
            },
            callbacks: .init(onAuthenticated: { _, _ in connected.fulfill() },
                             onInbound: { _, _ in },
                             onExhausted: { _ in XCTFail("the tunnel must not be given up") },
                             onEvent: { name, _ in log.event(name) }))

        c.start(signals: NetworkSignals())
        wait(for: [connected], timeout: 5)

        let movedOver = XCTestExpectation(description: "the standby took over")
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
            if c.activeServer?.id == ServerID("second") { movedOver.fulfill() }
        }
        wait(for: [movedOver], timeout: 5)

        XCTAssertTrue(log.allEvents.contains("standbyPromoted"),
                      "the drop should have been absorbed by the standby, events: \(log.allEvents)")
        // Two dials for the two relays, plus the standby warmed for the relay
        // now carrying the tunnel. What must NOT appear is a redial of the
        // relay that just died.
        XCTAssertFalse(log.allDials.dropFirst().contains(ServerID("first")),
                       "the dead relay must not be redialled: \(log.allDials)")
    }
}
