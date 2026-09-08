#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

/// Exercises the real transport against the real Worker.
///
/// This is deliberately a live test rather than a mock: every bug that made the
/// tunnel fail was in the boundary between the client, the Worker and the relay
/// — a WebSocket frame arriving as a type that decodes to zero bytes, a runtime
/// hang detector closing the socket — and a mock would have passed through all
/// of them. It skips when the Worker or the network is unavailable so it cannot
/// fail the suite offline.
final class WebSocketTransportTests: XCTestCase {

    /// A VPN Gate relay that answers on TCP 443. If it retires the test skips
    /// rather than fails; the point is the transport, not this host.
    private let relayHost = "219.100.37.196"
    private let relayPort: UInt16 = 443

    /// OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2: a 2-byte length prefix then
    /// opcode 0x38 and a session id. A conforming server must answer with
    /// opcode 0x40 (P_CONTROL_HARD_RESET_SERVER_V2).
    private let hardReset = Data([0x00, 0x0e, 0x38, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00])

    /// The field failure this guards: the Worker declined a relay in the pool
    /// and nothing acted on the verdict, so OpenVPN 3 redialled the same dead
    /// host on its own ten-second timer and a handover that should have taken
    /// three seconds took twenty-six.
    ///
    /// 203.0.113.1 is TEST-NET-3 and can never be on the VPN Gate list, so the
    /// Worker answers `0x00` for it every time.
    func testADeclinedRelayIsReportedAsUnusable() throws {
        let token = ProcessInfo.processInfo.environment["SWEEP_TUNNEL_TOKEN"] ?? ""
        try XCTSkipIf(token.isEmpty, "set SWEEP_TUNNEL_TOKEN to run the live tunnel test")

        // The transport dials the Worker by address, from a cache the app fills
        // while it is still outside the tunnel. A test process has no such
        // cache, so resolve it here — otherwise this exercises the no-address
        // path rather than the Worker's verdict.
        let suite = "sweep.test.\(UUID().uuidString)"
        let settings = RelayTunnelSettings(enabled: true,
                                           workerURL: WebSocketTransport.defaultWorkerURL,
                                           token: token)
        let resolved = settings.workerAddresses(appGroup: suite)
        try XCTSkipIf(resolved.isEmpty, "could not resolve the Worker")
        RelayTunnelSettings.cache(workerAddresses: resolved, appGroup: suite)

        let transport = WebSocketTransport(token: token, host: "203.0.113.1", port: 443,
                                           appGroup: suite)
        let unusable = expectation(description: "the transport reports the relay unusable")
        transport.onUnusable = { unusable.fulfill() }
        let localPort = try transport.start()
        defer { transport.stop() }

        // Dialling loopback is what makes the transport open the Worker leg.
        let connection = NWConnection(host: "127.0.0.1",
                                      port: NWEndpoint.Port(rawValue: localPort)!,
                                      using: .tcp)
        connection.start(queue: .global())
        defer { connection.cancel() }

        // Comfortably inside OpenVPN 3's ten-second retry, which is the whole
        // point of bounding it.
        wait(for: [unusable], timeout: 9)
    }

    /// The redial budget only helps if it fits inside the window the rest of the
    /// stack allows. Spend longer than OpenVPN 3's own retry and the core gives
    /// up on the relay before the reattach that would have saved it lands, which
    /// is the exact failure the Durable Object exists to remove.
    func testTheRedialBudgetFitsInsideTheStatusDeadline() {
        let spent = Double(WebSocketTransport.redialBudget) * WebSocketTransport.redialBackoff
        XCTAssertLessThan(spent, WebSocketTransport.statusDeadline)
        XCTAssertGreaterThan(WebSocketTransport.redialBudget, 1)
    }

    /// The Worker matches a redial to a live relay socket by this id alone. If
    /// it ever varied per attempt, every reattach would silently become a fresh
    /// relay connection and a full OpenVPN renegotiation — the thing that was
    /// happening every few seconds before.
    func testTheSessionIdIsStableAcrossRedials() {
        let transport = WebSocketTransport(token: "t", host: "203.0.113.1", port: 443,
                                           appGroup: "sweep.test.\(UUID().uuidString)")
        let session = UUID().uuidString
        let first = transport.tunnelPath(session: session)
        let second = transport.tunnelPath(session: session)
        XCTAssertEqual(first, second)
        XCTAssertTrue(first.contains("s=\(session)"), first)
    }

    /// `stop()` used to cancel only the listener. Every leg already bridged
    /// kept running — its loopback socket, its Worker connection and its
    /// WebSocket — while the transport that owned them was released. When the
    /// Worker then closed with `1000 "eof"`, the handler reached for a `self`
    /// that no longer existed and bailed, so the relay-gone verdict never
    /// reached the coordinator and nothing handed over. That is the 20-35 s of
    /// dead tunnel in the field log, and the `?` in `relay ? dropped the
    /// session` is the deallocated transport signing its own name.
    ///
    /// A leg must not outlive the transport that owns it. The stand-in Worker
    /// here accepts and then says nothing, which is what keeps the leg alive
    /// long enough for `stop()` to be the thing that ends it — an unroutable
    /// address would have the leg tear itself down and prove nothing.
    func testStoppingTheTransportTearsDownLegsItAlreadyBridged() throws {
        // A silent stand-in for the Worker, so the leg stays up.
        let sinkParams = NWParameters.tcp
        sinkParams.allowLocalEndpointReuse = true
        let sink = try NWListener(using: sinkParams)
        let accepted = expectation(description: "the leg reached the stand-in Worker")
        accepted.assertForOverFulfill = false
        let listening = expectation(description: "stand-in Worker listening")
        final class Held: @unchecked Sendable { var connections: [NWConnection] = [] }
        let held = Held()
        sink.newConnectionHandler = { connection in
            connection.start(queue: .global())
            held.connections.append(connection)
            accepted.fulfill()
        }
        sink.stateUpdateHandler = { if case .ready = $0 { listening.fulfill() } }
        sink.start(queue: .global())
        defer { sink.cancel() }
        wait(for: [listening], timeout: 5)
        let sinkPort = try XCTUnwrap(sink.port?.rawValue)
        XCTAssertGreaterThan(sinkPort, 0)

        let group = "sweep.test.\(UUID().uuidString)"
        RelayTunnelSettings.cache(workerAddresses: ["127.0.0.1"], appGroup: group)
        let transport = WebSocketTransport(
            workerURL: URL(string: "https://127.0.0.1:\(sinkPort)/tcp")!,
            token: "t", host: "203.0.113.1", port: 443, appGroup: group)
        let localPort = try transport.start()

        let ended = expectation(description: "the leg was torn down by stop()")
        // Teardown surfaces both as a completed read and as a cancelled state.
        ended.assertForOverFulfill = false
        let connection = NWConnection(host: "127.0.0.1",
                                      port: NWEndpoint.Port(rawValue: localPort)!,
                                      using: .tcp)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1) {
                    data, _, isComplete, error in
                    if isComplete || error != nil || (data?.isEmpty ?? true) { ended.fulfill() }
                }
            case .failed, .cancelled:
                ended.fulfill()
            default:
                break
            }
        }
        connection.start(queue: .global())
        defer { connection.cancel() }

        wait(for: [accepted], timeout: 5)
        // The leg is up and waiting on a Worker that will never answer. Only
        // stop() can end it now.
        transport.stop()
        wait(for: [ended], timeout: 5)
    }

    func testRelayAnswersThroughTheWorkerTunnel() throws {
        let token = ProcessInfo.processInfo.environment["SWEEP_TUNNEL_TOKEN"] ?? ""
        try XCTSkipIf(token.isEmpty, "set SWEEP_TUNNEL_TOKEN to run the live tunnel test")

        let transport = WebSocketTransport(token: token, host: relayHost, port: relayPort)
        let localPort = try transport.start()
        defer { transport.stop() }
        XCTAssertGreaterThan(localPort, 0)

        let replied = expectation(description: "relay answers through the tunnel")
        // A box rather than a captured var: the callbacks run on the network
        // queue, and Swift 6 will not let concurrent code mutate a local.
        final class Box: @unchecked Sendable { var data = Data() }
        let box = Box()
        let packet = hardReset

        let connection = NWConnection(host: "127.0.0.1",
                                      port: NWEndpoint.Port(rawValue: localPort)!,
                                      using: .tcp)
        connection.stateUpdateHandler = { state in
            guard case .ready = state else { return }
            connection.send(content: packet, completion: .contentProcessed { _ in })
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                if let data, !data.isEmpty { box.data = data; replied.fulfill() }
            }
        }
        connection.start(queue: .global())
        defer { connection.cancel() }

        let outcome = XCTWaiter().wait(for: [replied], timeout: 30)
        try XCTSkipUnless(outcome == .completed, "relay or network unavailable")

        // Byte 2 is the opcode; 0x40 is the server's hard-reset.
        let reply = box.data
        XCTAssertGreaterThanOrEqual(reply.count, 3)
        XCTAssertEqual(reply[reply.startIndex + 2], 0x40,
                       "expected P_CONTROL_HARD_RESET_SERVER_V2 back through the tunnel")
    }
}
#endif
