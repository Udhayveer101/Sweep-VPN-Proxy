import Foundation
import Network
import SweepVPNCore

/// One rung of the ladder. Implementations own their transport and their crypto
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
    /// The rung needs a credential the signed bundle did not carry.
    case missingCredential(ProtocolRung)
}

public enum AdapterFactory {
    /// Rungs that actually exist in this build. A rung that cannot run must fail
    /// loudly rather than look like a working tunnel.
    /// IKEv2 is real but runs as a kernel profile (`IKEv2Configurator`), not as
    /// a packet-tunnel adapter, so it is not in this set.
    public static let implementedRungs: Set<ProtocolRung> = [
        .wireGuardUDP, .wireGuardUDP443, .wireGuardQUIC,
        .wireGuardTLS, .shadowsocks2022, .wireGuardTCP,
    ]

    /// Rungs the app can offer at all.
    ///
    /// IKEv2 is deliberately absent. `IKEv2Configurator` exists but no code path
    /// calls it, so offering the rung in the picker promised a fallback that
    /// could never engage. It also installs into `NEVPNManager.shared()` — the
    /// single system-wide personal-VPN slot — which would clobber any IKEv2
    /// profile the user already has. Re-add it only once it is actually wired
    /// into the ladder and that clobbering is handled.
    public static let availableRungs: Set<ProtocolRung> = implementedRungs

    public static func make(rung: ProtocolRung, server: Server, privateKeyBase64: String,
                            presharedKeyBase64: String?, keepalive: Int?) throws -> TunnelAdapter {
        guard implementedRungs.contains(rung) else { throw AdapterFactoryError.rungNotImplemented(rung) }
        guard let endpoint = server.endpoints.first(where: { $0.rung == rung }) else {
            throw AdapterFactoryError.noEndpoint(rung)
        }
        let transport = try TransportFactory.make(rung: rung, endpoint: endpoint,
                                                  sni: endpoint.sni,
                                                  secret: endpoint.secretData)
        return WireGuardAdapter(rung: rung, server: server, endpoint: endpoint,
                                transport: transport, privateKeyBase64: privateKeyBase64,
                                presharedKeyBase64: presharedKeyBase64, keepalive: keepalive)
    }
}
