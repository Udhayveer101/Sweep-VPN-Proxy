import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// The field log showed `rungStarted: OVPN/TCP` twice in the same millisecond,
/// two `relayTunnelUp` loopback ports, two OpenVPN sessions CONNECTED, and only
/// one `rungWon`. The second adapter overwrote the first in `racing`, so the
/// first was never stopped and never stoppable: it spent the rest of the
/// session dialling relays, burning them, and reporting `wssFailed` under a
/// rung it no longer owned — which is what the user experienced as the tunnel
/// collapsing minutes after it came up.
///
/// The trigger is that retiring an adapter *causes a failure report*: stopping
/// the OpenVPN core makes it emit DISCONNECTED. That report arrived after the
/// replacement attempt had been armed, and armed a second one.
final class DuplicateAttemptTests: XCTestCase {

    private func relay(_ id: String, load: Double) -> Server {
        Server(id: ServerID(id), name: id, countryCode: "JP", publicKey: "",
               endpoints: [.init(host: id, port: 443, rung: .openVPNTCP)],
               dnsServers: ["8.8.8.8"], ipv4Address: "10.0.0.2",
               load: load, provider: "VPN Gate")
    }

    private final class Dials: @unchecked Sendable {
        private var ids: [ServerID] = []
        private let lock = NSLock()
        func append(_ id: ServerID) { lock.lock(); ids.append(id); lock.unlock() }
        var all: [ServerID] { lock.lock(); defer { lock.unlock() }; return ids }
    }

    /// A throughput handover stops the live adapter and arms the next relay.
    /// The stopped adapter's DISCONNECTED must not arm a second one.
    func testAHandoverStartsExactlyOneReplacementAttempt() {
        let pool = (0..<6).map { relay("r\($0)", load: Double($0) / 10) }
        let dials = Dials()
        var constants = AutoModeConstants()
        constants.raceStagger = 0.01
        constants.raceDeadline = 0.5
        constants.slowRungDeadline = 0.5
        let up = expectation(description: "connected")
        up.assertForOverFulfill = false

        let c = ConnectionCoordinator(
            engine: AutoModeEngine(constants: constants,
                                   preference: .forced(.openVPNTCP),
                                   enabledRungs: [.openVPNTCP]),
            catalog: ServerCatalog(servers: pool, rungs: [.openVPNTCP]),
            memory: NetworkMemory(),
            constants: constants,
            build: { rung, server in
                dials.append(server.id)
                return FakeAdapter(rung: rung,
                                   behaviour: .authenticateThenFailOnStop(after: 0.02))
            },
            callbacks: .init(onAuthenticated: { _, _ in up.fulfill() },
                             onInbound: { _, _ in },
                             onExhausted: { _ in }))

        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)
        XCTAssertEqual(dials.all.count, 1, "the connect itself dialled more than one relay")

        // Two sub-floor samples, past the dwell: a voluntary handover.
        let later = Date().addingTimeInterval(120)
        c.noteThroughput(bytesPerSecond: 9 * 1024, now: later)
        c.noteThroughput(bytesPerSecond: 9 * 1024, now: later)

        let settled = expectation(description: "settled")
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { settled.fulfill() }
        wait(for: [settled], timeout: 5)

        // One handover, one new relay. Two means the stopped adapter armed an
        // attempt of its own alongside the intended one — the duplicate tunnel.
        XCTAssertEqual(dials.all.count, 2,
                       "one handover dialled \(dials.all.count) relays: \(dials.all)")
        XCTAssertEqual(Set(dials.all).count, dials.all.count, "a relay was dialled twice")
    }

    /// The same shape from the other direction: the live tunnel dies. The
    /// coordinator stops the adapter as part of handling that, and the stop's
    /// own failure report must not count as a second death.
    func testALiveTunnelDropStartsExactlyOneReplacementAttempt() {
        let pool = (0..<6).map { relay("r\($0)", load: Double($0) / 10) }
        let dials = Dials()
        var constants = AutoModeConstants()
        constants.raceStagger = 0.01
        constants.raceDeadline = 0.5
        constants.slowRungDeadline = 0.5
        let up = expectation(description: "connected")
        up.assertForOverFulfill = false

        let c = ConnectionCoordinator(
            engine: AutoModeEngine(constants: constants,
                                   preference: .forced(.openVPNTCP),
                                   enabledRungs: [.openVPNTCP]),
            catalog: ServerCatalog(servers: pool, rungs: [.openVPNTCP]),
            memory: NetworkMemory(),
            constants: constants,
            build: { rung, server in
                dials.append(server.id)
                // First relay dies on its own after coming up; the rest hold.
                let behaviour: FakeAdapter.Behaviour = server.id == ServerID("r0")
                    ? .authenticateThenDrop(after: 0.02, dropAfter: 0.1)
                    : .authenticateThenFailOnStop(after: 0.02)
                return FakeAdapter(rung: rung, behaviour: behaviour)
            },
            callbacks: .init(onAuthenticated: { _, _ in up.fulfill() },
                             onInbound: { _, _ in },
                             onExhausted: { _ in }))

        c.start(signals: NetworkSignals())
        wait(for: [up], timeout: 5)

        let settled = expectation(description: "settled")
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { settled.fulfill() }
        wait(for: [settled], timeout: 5)

        XCTAssertEqual(dials.all.count, 2,
                       "one drop dialled \(dials.all.count) relays: \(dials.all)")
        XCTAssertEqual(Set(dials.all).count, dials.all.count, "a relay was dialled twice")
    }
}
