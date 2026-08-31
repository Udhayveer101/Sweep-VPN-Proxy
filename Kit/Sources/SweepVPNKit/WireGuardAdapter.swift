import Foundation
import Network
import SweepVPNCore
import SweepWireGuardC

/// Every WireGuard rung: one boringtun tunnel plus whichever `PacketTransport`
/// the rung selects. The crypto is identical on all rungs — only the envelope
/// changes — so a fallback never trades security for reachability.
public final class WireGuardAdapter: TunnelAdapter, @unchecked Sendable {
    public let rung: ProtocolRung

    private let server: Server
    private let endpoint: ServerEndpoint
    private let privateKeyBase64: String
    private var presharedKeyBase64: String?
    private let keepalive: UInt16
    private let transport: PacketTransport

    private var tunnel: OpaquePointer?
    private let queue = DispatchQueue(label: "vpn.sweep.wg", qos: .userInitiated)
    private var timer: DispatchSourceTimer?
    private var authenticated = false

    private var onAuthenticated: (@Sendable () -> Void)?
    private var onInbound: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var onFailure: (@Sendable (TunnelErrorKind) -> Void)?

    private static let bufferSize = 65_536

    public init(rung: ProtocolRung, server: Server, endpoint: ServerEndpoint,
                transport: PacketTransport, privateKeyBase64: String,
                presharedKeyBase64: String?, keepalive: Int?) {
        self.rung = rung
        self.server = server
        self.endpoint = endpoint
        self.transport = transport
        self.privateKeyBase64 = privateKeyBase64
        self.presharedKeyBase64 = presharedKeyBase64
        self.keepalive = UInt16(keepalive ?? 0)
    }

    deinit { stop() }

    public func start(onAuthenticated: @escaping @Sendable () -> Void,
                      onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                      onFailure: @escaping @Sendable (TunnelErrorKind) -> Void) {
        self.onAuthenticated = onAuthenticated
        self.onInbound = onInbound
        self.onFailure = onFailure

        tunnel = privateKeyBase64.withCString { sk in
            server.publicKey.withCString { pk in
                if let psk = presharedKeyBase64 {
                    return psk.withCString { p in sweepwg_new(sk, pk, p, keepalive, 1) }
                }
                return sweepwg_new(sk, pk, nil, keepalive, 1)
            }
        }
        guard tunnel != nil else { return onFailure(.internalFailure) }

        transport.start(
            onReady: { [weak self] in
                guard let self else { return }
                self.queue.async {
                    self.handshake()
                    self.startTimer()
                }
            },
            onDatagram: { [weak self] data in
                self?.queue.async { self?.handleInbound(data) }
            },
            onFailure: { [weak self] in
                self?.onFailure?(.allRungsFailed)
            })
    }

    public func stop() {
        timer?.cancel(); timer = nil
        transport.stop()
        if let t = tunnel { sweepwg_free(t) }
        tunnel = nil
        authenticated = false
    }

    public func reassert() {
        queue.async { [weak self] in
            self?.authenticated = false
            self?.handshake()
        }
    }

    /// Install a new preshared key (the ML-KEM-768 hybrid PSK) and re-handshake.
    public func applyPostQuantumPSK(_ pskBase64: String) {
        queue.async { [weak self] in
            guard let self, let t = self.tunnel else { return }
            let ok = self.privateKeyBase64.withCString { sk in
                self.server.publicKey.withCString { pk in
                    pskBase64.withCString { psk in
                        sweepwg_set_psk(t, sk, pk, psk, self.keepalive, 1)
                    }
                }
            }
            guard ok == SWEEPWG_DONE else { return }
            self.presharedKeyBase64 = pskBase64
            self.authenticated = false
            self.handshake()
        }
    }

    public var lastHandshakeAgeSeconds: Int64 {
        guard let t = tunnel else { return -1 }
        return sweepwg_seconds_since_handshake(t)
    }

    public var transferred: (tx: UInt64, rx: UInt64) {
        guard let t = tunnel else { return (0, 0) }
        var tx: UInt64 = 0, rx: UInt64 = 0
        _ = sweepwg_transfer(t, &tx, &rx)
        return (tx, rx)
    }

    // MARK: - Packet paths

    public func send(packets: [Data], protocols: [NSNumber]) {
        queue.async { [weak self] in
            guard let self, let t = self.tunnel else { return }
            var out = [UInt8](repeating: 0, count: Self.bufferSize)
            for packet in packets {
                var written = 0
                let r = packet.withUnsafeBytes { src in
                    sweepwg_encapsulate(t, src.bindMemory(to: UInt8.self).baseAddress, packet.count,
                                        &out, out.count, &written)
                }
                if r == SWEEPWG_WRITE_TO_NETWORK, written > 0 {
                    self.transport.send(Data(out[0..<written]))
                }
                // Any other result means "drop" — a packet is never forwarded
                // outside the tunnel as a fallback.
            }
        }
    }

    private func handleInbound(_ data: Data) {
        guard let t = tunnel else { return }
        var out = [UInt8](repeating: 0, count: Self.bufferSize)
        var written = 0
        let r = data.withUnsafeBytes { src in
            sweepwg_decapsulate(t, src.bindMemory(to: UInt8.self).baseAddress, data.count,
                                &out, out.count, &written)
        }
        switch r {
        case SWEEPWG_WRITE_TO_NETWORK:
            if written > 0 { transport.send(Data(out[0..<written])) }
            drainNetworkQueue()
            noteAuthenticatedIfNeeded()
        case SWEEPWG_WRITE_TO_TUNNEL_V4:
            noteAuthenticatedIfNeeded()
            if written > 0 { onInbound?([Data(out[0..<written])], [NSNumber(value: AF_INET)]) }
        case SWEEPWG_WRITE_TO_TUNNEL_V6:
            noteAuthenticatedIfNeeded()
            if written > 0 { onInbound?([Data(out[0..<written])], [NSNumber(value: AF_INET6)]) }
        default:
            break   // forged, replayed or malformed — dropped
        }
    }

    private func drainNetworkQueue() {
        guard let t = tunnel else { return }
        var out = [UInt8](repeating: 0, count: Self.bufferSize)
        while true {
            var written = 0
            let r = sweepwg_decapsulate(t, nil, 0, &out, out.count, &written)
            guard r == SWEEPWG_WRITE_TO_NETWORK, written > 0 else { return }
            transport.send(Data(out[0..<written]))
        }
    }

    private func noteAuthenticatedIfNeeded() {
        guard !authenticated, lastHandshakeAgeSeconds >= 0 else { return }
        authenticated = true
        onAuthenticated?()
    }

    private func handshake() {
        guard let t = tunnel else { return }
        var out = [UInt8](repeating: 0, count: Self.bufferSize)
        var written = 0
        if sweepwg_force_handshake(t, &out, out.count, &written) == SWEEPWG_WRITE_TO_NETWORK,
           written > 0 {
            transport.send(Data(out[0..<written]))
        }
    }

    /// One timer drives rekey, keepalive and handshake retry — no polling loops.
    private func startTimer() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 1.0, leeway: .milliseconds(250))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func tick() {
        guard let t = tunnel else { return }
        var out = [UInt8](repeating: 0, count: Self.bufferSize)
        var written = 0
        if sweepwg_tick(t, &out, out.count, &written) == SWEEPWG_WRITE_TO_NETWORK, written > 0 {
            transport.send(Data(out[0..<written]))
        }
    }
}
