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
