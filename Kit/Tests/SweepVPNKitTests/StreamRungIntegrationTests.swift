import XCTest
import Network
import CryptoKit
import SweepVPNCore
import SweepWireGuardC
@testable import SweepVPNKit

/// Proves the whole non-UDP path really interoperates: the Swift stream
/// transport's framing → the real `sweepbridge` server binary → a real
/// WireGuard peer, and back. This is the rung that has to work when a network
/// drops all UDP, so it is tested against the actual server component rather
/// than a Swift stand-in.
final class StreamRungIntegrationTests: XCTestCase {
    /// Marks whether the test that installed a callback is still running.
    final class LiveFlag: @unchecked Sendable {
        private var live = true
        private let lock = NSLock()
        var isLive: Bool { lock.lock(); defer { lock.unlock() }; return live }
        func retire() { lock.lock(); live = false; lock.unlock() }
    }


    static var bridgeURL: URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("sweep-vpn/Server/sweepbridge/target/release/sweepbridge")
    }

    /// Ask the kernel for an unused TCP port and release it immediately.
    func freePort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw XCTSkip("cannot open a socket") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw XCTSkip("cannot bind") }
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else { throw XCTSkip("cannot read port") }
        return UInt16(bigEndian: out.sin_port)
    }

    /// Poll until something accepts TCP on `port`.
    func waitUntilAccepting(port: UInt16, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            defer { close(fd) }
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            addr.sin_port = port.bigEndian
            let ok = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if ok == 0 { return true }
            usleep(100_000)
        }
        return false
    }

    func testWireGuardOverTCPThroughTheRealBridge() throws {
        guard FileManager.default.isExecutableFile(atPath: Self.bridgeURL.path) else {
            throw XCTSkip("sweepbridge not built — run `cargo build --release` in Server/sweepbridge")
        }

        let clientKey = Curve25519.KeyAgreement.PrivateKey()
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let peer = try AdapterIntegrationTests.LoopbackPeer(
            privateKeyB64: serverKey.rawRepresentation.base64EncodedString(),
            peerPublicKeyB64: clientKey.publicKey.rawRepresentation.base64EncodedString(),
            transport: .udp)
        defer { peer.stop() }
        let settle = XCTestExpectation(description: "peer bound")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { settle.fulfill() }
        wait(for: [settle], timeout: 2)

        let bridgePort = try freePort()
        let process = Process()
        process.executableURL = Self.bridgeURL
        process.arguments = ["--tcp", "127.0.0.1:\(bridgePort)",
                             "--wireguard", "127.0.0.1:\(peer.port)"]
        process.standardError = FileHandle.nullDevice
        try process.run()
        defer { process.terminate() }
        // Wait for the bridge to actually accept a connection rather than
        // guessing at a start-up delay — a fixed sleep is how this test flakes.
        XCTAssertTrue(waitUntilAccepting(port: bridgePort, timeout: 10),
                      "sweepbridge never started listening")

        // Same server, but reached over the TCP rung on the bridge's port.
        let server = Server(id: "bridge", name: "Bridge", countryCode: "ZZ",
                            publicKey: serverKey.publicKey.rawRepresentation.base64EncodedString(),
                            endpoints: [.init(host: "127.0.0.1", port: bridgePort, rung: .wireGuardTCP)],
                            dnsServers: ["127.0.0.1"], ipv4Address: "10.64.0.2")

        let adapter = try AdapterFactory.make(rung: .wireGuardTCP, server: server,
                                              privateKeyBase64: clientKey.rawRepresentation.base64EncodedString(),
                                              presharedKeyBase64: nil, keepalive: nil)
        defer { adapter.stop() }

        // The adapter keeps running while it is torn down; a late failure
        // callback must not fail whichever test happens to be running by then.
        let live = LiveFlag()
        defer { live.retire() }

        let authenticated = XCTestExpectation(description: "handshake over TCP")
        let inbound = XCTestExpectation(description: "packet returned through the tunnel")
        let packet = AdapterIntegrationTests.samplePacket
        peer.onPlaintext = { _ in }

        adapter.start(onAuthenticated: { authenticated.fulfill() },
                      onInbound: { packets, _ in if packets.first == packet { inbound.fulfill() } },
                      onFailure: { kind in
                          if live.isLive { XCTFail("TCP rung failed: \(kind)") }
                      })

        wait(for: [authenticated], timeout: 15)
        XCTAssertEqual(adapter.rung, .wireGuardTCP)
        adapter.send(packets: [packet], protocols: [NSNumber(value: AF_INET)])
        wait(for: [inbound], timeout: 15)
        XCTAssertGreaterThan(adapter.transferred.rx, 0)
    }

    /// A rung the build cannot run must fail loudly rather than quietly falling
    /// back to a weaker envelope.
    func testShadowsocksRungRefusesWithoutItsPreSharedKey() {
        let server = Server(id: "s", name: "s", countryCode: "ZZ", publicKey: "pk",
                            endpoints: [.init(host: "127.0.0.1", port: 443, rung: .shadowsocks2022)],
                            dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")
        XCTAssertThrowsError(try AdapterFactory.make(rung: .shadowsocks2022, server: server,
                                                     privateKeyBase64: "k", presharedKeyBase64: nil,
                                                     keepalive: nil)) {
            XCTAssertEqual($0 as? AdapterFactoryError, .missingCredential(.shadowsocks2022))
        }
    }

    func testEveryImplementedRungCanBuildATransport() throws {
        let psk = Data(repeating: 7, count: 32).base64EncodedString()
        // Only the WireGuard rungs are transports carrying our tunnel. OpenVPN
        // brings its own transport inside OpenVPN 3 and deliberately never
        // reaches TransportFactory, which is why it is excluded here rather
        // than given a stub.
        for rung in AdapterFactory.implementedRungs.filter(\.isOwnWireGuardTunnel) {
            let endpoint = ServerEndpoint(host: "127.0.0.1", port: 443, rung: rung,
                                          sni: "www.example.com", secret: psk)
            let transport = try TransportFactory.make(rung: rung, endpoint: endpoint,
                                                      sni: endpoint.sni, secret: endpoint.secretData)
            XCTAssertEqual(transport.rung, rung)
            transport.stop()
        }
    }

    /// The other half of that rule: asking TransportFactory for an OpenVPN rung
    /// must fail loudly rather than quietly hand back something that is not
    /// OpenVPN.
    func testOpenVPNRungsAreNotTransports() {
        for rung in [ProtocolRung.openVPNUDP, .openVPNTCP] {
            let endpoint = ServerEndpoint(host: "127.0.0.1", port: 443, rung: rung)
            XCTAssertThrowsError(try TransportFactory.make(rung: rung, endpoint: endpoint,
                                                           sni: nil, secret: nil)) {
                XCTAssertEqual($0 as? AdapterFactoryError, .rungNotImplemented(rung))
            }
        }
    }
}
