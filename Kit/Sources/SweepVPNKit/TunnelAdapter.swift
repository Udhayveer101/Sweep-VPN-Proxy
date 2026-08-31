import Foundation
import Network
import SweepVPNCore

/// One rung of the ladder. Implementations own their socket and their crypto
/// state; the provider only sees packets and state changes.
public protocol TunnelAdapter: AnyObject, Sendable {
    var rung: ProtocolRung { get }
    /// Called with plaintext IP packets read from the tunnel interface.
    func send(packets: [Data], protocols: [NSNumber])
    /// Bring the adapter up. `onAuthenticated` fires only after the peer is
    /// cryptographically verified — the provider keeps the blackhole armed
    /// until then.
    func start(onAuthenticated: @escaping @Sendable () -> Void,
               onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
               onFailure: @escaping @Sendable (TunnelErrorKind) -> Void)
    func stop()
    /// Re-handshake after a network change (roaming).
    func reassert()
    var lastHandshakeAgeSeconds: Int64 { get }
    var transferred: (tx: UInt64, rx: UInt64) { get }
}

public enum AdapterFactoryError: Error, Equatable {
    /// A researched-but-not-yet-implemented rung. Never silently substituted.
    case rungNotImplemented(ProtocolRung)
    case noEndpoint(ProtocolRung)
}

public enum AdapterFactory {
    /// Rungs actually implemented in this build. Anything else must fail loudly:
    /// a rung that cannot run is not allowed to look like a working tunnel.
    public static let implementedRungs: Set<ProtocolRung> = [.wireGuardUDP, .ikev2]

    public static func make(rung: ProtocolRung, server: Server, privateKeyBase64: String,
                           presharedKeyBase64: String?, keepalive: Int?) throws -> TunnelAdapter {
        guard implementedRungs.contains(rung) else { throw AdapterFactoryError.rungNotImplemented(rung) }
        guard let endpoint = server.endpoints.first(where: { $0.rung == rung }) else {
            throw AdapterFactoryError.noEndpoint(rung)
        }
        switch rung {
        case .wireGuardUDP:
            return WireGuardAdapter(server: server, endpoint: endpoint,
                                    privateKeyBase64: privateKeyBase64,
                                    presharedKeyBase64: presharedKeyBase64,
                                    keepalive: keepalive)
        case .ikev2:
            // Rung 4 runs in the kernel via NEVPNProtocolIKEv2 and never uses a
            // packet-tunnel adapter — see IKEv2Configurator.
            throw AdapterFactoryError.rungNotImplemented(rung)
        default:
            throw AdapterFactoryError.rungNotImplemented(rung)
        }
    }
}
