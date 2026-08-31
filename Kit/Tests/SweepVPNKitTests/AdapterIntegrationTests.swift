import XCTest
import Network
import CryptoKit
import SweepVPNCore
import SweepWireGuardC
@testable import SweepVPNKit

/// End-to-end test of the *Swift* adapter (not just the C ABI): a real
/// WireGuard peer is run on loopback UDP using the same data plane, and the
/// adapter must handshake with it and carry a packet both ways.
final class AdapterIntegrationTests: XCTestCase {
    /// A minimal, valid IPv4 packet shared by the transport integration tests.
    static let samplePacket = Data(LoopbackPeer.samplePacketBytes)


    /// Minimal in-process WireGuard peer bound to 127.0.0.1.
    final class LoopbackPeer: @unchecked Sendable {
        let listener: NWListener
        let tunnel: OpaquePointer
        var connection: NWConnection?
        let queue = DispatchQueue(label: "test.peer")
        var onPlaintext: ((Data) -> Void)?

        static let samplePacketBytes: [UInt8] = {
            var p = [UInt8](repeating: 0, count: 20)
            p[0] = 0x45; p[3] = 20; p[9] = 1
            p[12...15] = [10, 64, 0, 2][0...3]
            p[16...19] = [10, 64, 0, 1][0...3]
            return p
        }()

        init(privateKeyB64: String, peerPublicKeyB64: String, transport: NWParameters = .udp) throws {
            tunnel = privateKeyB64.withCString { sk in
                peerPublicKeyB64.withCString { pk in sweepwg_new(sk, pk, nil, 0, 2)! }
            }
            listener = try NWListener(using: transport, on: .any)
            listener.newConnectionHandler = { [weak self] conn in
                guard let self else { return }
                self.connection = conn
                conn.stateUpdateHandler = { _ in }
                conn.start(queue: self.queue)
                self.receive(on: conn)
            }
            listener.start(queue: queue)
        }

        var port: UInt16 { listener.port?.rawValue ?? 0 }

        private func receive(on conn: NWConnection) {
            conn.receiveMessage { [weak self] data, _, _, error in
                guard let self else { return }
                if let data, !data.isEmpty { self.handle(data, on: conn) }
                if error == nil { self.receive(on: conn) }
            }
        }

        private func handle(_ data: Data, on conn: NWConnection) {
            var out = [UInt8](repeating: 0, count: 65_536)
            var n = 0
            let r = data.withUnsafeBytes {
                sweepwg_decapsulate(tunnel, $0.bindMemory(to: UInt8.self).baseAddress, data.count,
                                    &out, out.count, &n)
            }
            switch r {
            case SWEEPWG_WRITE_TO_NETWORK:
                if n > 0 { conn.send(content: Data(out[0..<n]), completion: .idempotent) }
            case SWEEPWG_WRITE_TO_TUNNEL_V4, SWEEPWG_WRITE_TO_TUNNEL_V6:
                let plaintext = Data(out[0..<n])
                onPlaintext?(plaintext)
                echo(plaintext, on: conn)
            default: break
            }
        }

        /// Send a packet back through the tunnel so the adapter's inbound path runs.
        private func echo(_ packet: Data, on conn: NWConnection) {
            var out = [UInt8](repeating: 0, count: 65_536)
            var n = 0
            let r = packet.withUnsafeBytes {
                sweepwg_encapsulate(tunnel, $0.bindMemory(to: UInt8.self).baseAddress, packet.count,
                                    &out, out.count, &n)
            }
            if r == SWEEPWG_WRITE_TO_NETWORK, n > 0 {
                conn.send(content: Data(out[0..<n]), completion: .idempotent)
            }
        }

        func stop() { listener.cancel(); connection?.cancel(); sweepwg_free(tunnel) }
    }

    func testAdapterHandshakesAndCarriesTrafficBothWays() throws {
        let clientKey = Curve25519.KeyAgreement.PrivateKey()
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let clientPrivB64 = clientKey.rawRepresentation.base64EncodedString()
        let clientPubB64 = clientKey.publicKey.rawRepresentation.base64EncodedString()
        let serverPrivB64 = serverKey.rawRepresentation.base64EncodedString()
        let serverPubB64 = serverKey.publicKey.rawRepresentation.base64EncodedString()

        let peer = try LoopbackPeer(privateKeyB64: serverPrivB64, peerPublicKeyB64: clientPubB64)
        defer { peer.stop() }
        // Give the listener a moment to bind.
        let bound = XCTestExpectation(description: "listener bound")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { bound.fulfill() }
        wait(for: [bound], timeout: 2)
        XCTAssertGreaterThan(peer.port, 0)

        let server = Server(id: "loop", name: "Loopback", countryCode: "ZZ",
                            publicKey: serverPubB64,
                            endpoints: [.init(host: "127.0.0.1", port: peer.port, rung: .wireGuardUDP)],
                            dnsServers: ["127.0.0.1"], ipv4Address: "10.64.0.2")

        let adapter = try AdapterFactory.make(rung: .wireGuardUDP, server: server,
                                              privateKeyBase64: clientPrivB64,
                                              presharedKeyBase64: nil, keepalive: nil)
        let authenticated = XCTestExpectation(description: "handshake completed")
        let inbound = XCTestExpectation(description: "packet received back through the tunnel")
        let serverSaw = XCTestExpectation(description: "server decrypted the packet")

        let packet = Self.samplePacket
        peer.onPlaintext = { received in
            if received == packet { serverSaw.fulfill() }
        }

        adapter.start(onAuthenticated: { authenticated.fulfill() },
                      onInbound: { packets, _ in if packets.first == packet { inbound.fulfill() } },
                      onFailure: { XCTFail("adapter failed: \($0)") })
        defer { adapter.stop() }

        wait(for: [authenticated], timeout: 10)
        XCTAssertGreaterThanOrEqual(adapter.lastHandshakeAgeSeconds, 0)

        adapter.send(packets: [packet], protocols: [NSNumber(value: AF_INET)])
        wait(for: [serverSaw, inbound], timeout: 10)

        let transfer = adapter.transferred
        XCTAssertGreaterThan(transfer.tx, 0)
        XCTAssertGreaterThan(transfer.rx, 0)
    }
}
