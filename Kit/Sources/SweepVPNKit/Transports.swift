import Foundation
import Network
import SweepVPNCore

/// Carries WireGuard datagrams across the network. Every implementation moves
/// the *same* bytes — the WireGuard tunnel is unmodified — so a rung change is
/// a change of envelope, never a change of cryptography.
public protocol PacketTransport: AnyObject, Sendable {
    var rung: ProtocolRung { get }
    func start(onReady: @escaping @Sendable () -> Void,
               onDatagram: @escaping @Sendable (Data) -> Void,
               onFailure: @escaping @Sendable () -> Void)
    func send(_ datagram: Data)
    func stop()
}

public enum TransportFactory {
    public static func make(rung: ProtocolRung, endpoint: ServerEndpoint,
                            sni: String?, secret: Data?) throws -> PacketTransport {
        let host = NWEndpoint.Host(endpoint.host)
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw AdapterFactoryError.noEndpoint(rung)
        }
        switch rung {
        case .wireGuardUDP, .wireGuardUDP443:
            return DatagramTransport(rung: rung, host: host, port: port, parameters: .udp)
        case .wireGuardQUIC:
            return DatagramTransport(rung: rung, host: host, port: port,
                                     parameters: quicParameters(sni: sni ?? endpoint.host))
        case .wireGuardTLS:
            return StreamTransport(rung: rung, host: host, port: port,
                                   parameters: tlsParameters(sni: sni ?? endpoint.host))
        case .wireGuardTCP:
            return StreamTransport(rung: rung, host: host, port: port, parameters: .tcp)
        case .shadowsocks2022:
            guard let secret, secret.count == 32 else { throw AdapterFactoryError.missingCredential(rung) }
            return ShadowsocksTransport(host: host, port: port, key: secret)
        case .ikev2:
            throw AdapterFactoryError.rungNotImplemented(.ikev2)   // kernel profile, not a transport
        case .openVPNUDP, .openVPNTCP:
            // OpenVPN is not a transport carrying our WireGuard tunnel — it is
            // its own protocol and needs its own client. Until that data plane
            // exists, the rung fails loudly here rather than quietly resolving
            // to something that is not OpenVPN.
            throw AdapterFactoryError.rungNotImplemented(rung)
        }
    }

    /// QUIC with a datagram stream: message-oriented like UDP, but the bytes on
    /// the wire are an ordinary QUIC/HTTP-3 flow to UDP/443.
    static func quicParameters(sni: String) -> NWParameters {
        let options = NWProtocolQUIC.Options(alpn: ["h3"])
        options.isDatagram = true
        options.maxDatagramFrameSize = 1500
        options.idleTimeout = 30_000
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, sni)
        sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv13)
        return NWParameters(quic: options)
    }

    /// Real TLS 1.3 to TCP/443 with a real SNI — a middlebox sees HTTPS.
    /// The TLS layer adds no security we rely on: WireGuard inside it is already
    /// authenticated and encrypted (vault Obfuscation-Is-Not-Security).
    static func tlsParameters(sni: String) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, sni)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "h2")
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 30
        return NWParameters(tls: tls, tcp: tcp)
    }
}

/// Message-oriented transports (UDP, QUIC datagrams): one send == one datagram.
public final class DatagramTransport: PacketTransport, @unchecked Sendable {
    public let rung: ProtocolRung
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "vpn.sweep.transport.dgram")
    private var failed = false

    init(rung: ProtocolRung, host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters) {
        self.rung = rung
        // Never let this socket be captured by the tunnel we are building.
        parameters.prohibitedInterfaceTypes = [.other]
        self.connection = NWConnection(host: host, port: port, using: parameters)
    }

    public func start(onReady: @escaping @Sendable () -> Void,
                      onDatagram: @escaping @Sendable (Data) -> Void,
                      onFailure: @escaping @Sendable () -> Void) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.receive(onDatagram: onDatagram, onFailure: onFailure)
                onReady()
            case .failed, .cancelled:
                self.reportFailure(onFailure)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func receive(onDatagram: @escaping @Sendable (Data) -> Void,
                         onFailure: @escaping @Sendable () -> Void) {
        connection.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { onDatagram(data) }
            if error != nil || (isComplete && data == nil) {
                self.reportFailure(onFailure)
            } else {
                self.receive(onDatagram: onDatagram, onFailure: onFailure)
            }
        }
    }

    private func reportFailure(_ onFailure: @escaping @Sendable () -> Void) {
        guard !failed else { return }
        failed = true
        onFailure()
    }

    public func send(_ datagram: Data) {
        connection.send(content: datagram, completion: .contentProcessed { _ in })
    }

    public func stop() { connection.cancel() }
}

/// Stream transports (TLS, plain TCP). WireGuard datagrams are framed with a
/// 2-byte big-endian length so datagram boundaries survive the byte stream.
public final class StreamTransport: PacketTransport, @unchecked Sendable {
    public let rung: ProtocolRung
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "vpn.sweep.transport.stream")
    private var buffer = Data()
    private var failed = false

    static let maxFrame = 65_535

    init(rung: ProtocolRung, host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters) {
        self.rung = rung
        parameters.prohibitedInterfaceTypes = [.other]
        self.connection = NWConnection(host: host, port: port, using: parameters)
    }

    public func start(onReady: @escaping @Sendable () -> Void,
                      onDatagram: @escaping @Sendable (Data) -> Void,
                      onFailure: @escaping @Sendable () -> Void) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.receive(onDatagram: onDatagram, onFailure: onFailure)
                onReady()
            case .failed, .cancelled:
                self.reportFailure(onFailure)
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func receive(onDatagram: @escaping @Sendable (Data) -> Void,
                         onFailure: @escaping @Sendable () -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.queue.async { self.consume(data, onDatagram: onDatagram) }
            }
            if error != nil || isComplete {
                self.reportFailure(onFailure)
            } else {
                self.receive(onDatagram: onDatagram, onFailure: onFailure)
            }
        }
    }

    /// Deframe as many complete datagrams as the buffer holds. A frame claiming
    /// more than 64 KiB is a protocol violation — drop the connection instead of
    /// growing an unbounded buffer.
    private func consume(_ data: Data, onDatagram: @escaping @Sendable (Data) -> Void) {
        buffer.append(data)
        while buffer.count >= 2 {
            let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
            guard length > 0, length <= Self.maxFrame else {
                buffer.removeAll(keepingCapacity: false)
                connection.cancel()
                return
            }
            guard buffer.count >= length + 2 else { return }
            let start = buffer.startIndex + 2
            onDatagram(Data(buffer[start ..< start + length]))
            buffer.removeSubrange(buffer.startIndex ..< start + length)
        }
    }

    public func send(_ datagram: Data) {
        guard datagram.count <= Self.maxFrame else { return }
        var framed = Data([UInt8(datagram.count >> 8), UInt8(datagram.count & 0xFF)])
        framed.append(datagram)
        connection.send(content: framed, completion: .contentProcessed { _ in })
    }

    private func reportFailure(_ onFailure: @escaping @Sendable () -> Void) {
        guard !failed else { return }
        failed = true
        onFailure()
    }

    public func stop() { connection.cancel() }
}
