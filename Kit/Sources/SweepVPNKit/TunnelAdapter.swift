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
    /// Whether the tunnel still looks alive, judged the way *this protocol*
    /// allows. It exists because "handshake age" does not mean the same thing on
    /// every rung: WireGuard rekeys on a schedule, so a stale handshake is a
    /// dead path, while OpenVPN establishes its session once and would fail that
    /// test by simply staying connected. Each adapter answers for itself rather
    /// than the provider reinterpreting a number that means two things.
    ///
    /// Called on a timer, so implementations may keep sample-to-sample state.
    func sampleLiveness() -> Bool
    /// Settings the peer assigned at connect time. Nil for every WireGuard
    /// rung, where the address comes from the signed bundle before the tunnel
    /// starts; set for OpenVPN, where it arrives in PUSH_REPLY.
    var pushedSettings: PushedTunnelSettings? { get }
}

public extension TunnelAdapter {
    var pushedSettings: PushedTunnelSettings? { nil }

    /// WireGuard's rule, and the right default: the protocol rekeys about every
    /// two minutes, so a handshake older than that with no traffic means the
    /// path is gone. `-1` is "never handshaked", which is not alive either.
    func sampleLiveness() -> Bool {
        let age = lastHandshakeAgeSeconds
        return age >= 0 && age < TunnelLiveness.handshakeStaleAfter
    }
}

public enum TunnelLiveness {
    /// Roughly one and a half WireGuard rekey intervals.
    public static let handshakeStaleAfter: Int64 = 180
    /// How long an OpenVPN session is given to carry its first inbound bytes
    /// before silence counts against it. A relay that has assigned an address
    /// but sent nothing back yet is still connecting, not dead.
    public static let openVPNQuietGrace: TimeInterval = 90
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
    public static let implementedRungs: Set<ProtocolRung> = {
        var rungs: Set<ProtocolRung> = [
            .wireGuardUDP, .wireGuardUDP443, .wireGuardQUIC,
            .wireGuardTLS, .shadowsocks2022, .wireGuardTCP,
        ]
        #if os(macOS)
        // OpenVPN 3 is linked on macOS only so far — the iOS slice still needs
        // its static dependencies cross-compiled. Listing the rungs where they
        // do not exist would offer the user a relay they cannot reach.
        rungs.formUnion([.openVPNUDP, .openVPNTCP])
        #endif
        return rungs
    }()

    /// Rungs the app can offer at all.
    public static let availableRungs: Set<ProtocolRung> = implementedRungs

    public static func make(rung: ProtocolRung, server: Server, privateKeyBase64: String,
                            presharedKeyBase64: String?, keepalive: Int?) throws -> TunnelAdapter {
        guard implementedRungs.contains(rung) else { throw AdapterFactoryError.rungNotImplemented(rung) }
        guard let endpoint = server.endpoints.first(where: { $0.rung == rung }) else {
            throw AdapterFactoryError.noEndpoint(rung)
        }

        // OpenVPN is its own protocol, not our WireGuard tunnel in another
        // envelope, so it does not go through TransportFactory at all.
        if !rung.isOwnWireGuardTunnel {
            #if os(macOS)
            guard let adapter = OpenVPNTunnelAdapter(rung: rung, server: server,
                                                     endpoint: endpoint) else {
                throw AdapterFactoryError.missingCredential(rung)
            }
            return adapter
            #else
            throw AdapterFactoryError.rungNotImplemented(rung)
            #endif
        }

        let transport = try TransportFactory.make(rung: rung, endpoint: endpoint,
                                                  sni: endpoint.sni,
                                                  secret: endpoint.secretData)
        return WireGuardAdapter(rung: rung, server: server, endpoint: endpoint,
                                transport: transport, privateKeyBase64: privateKeyBase64,
                                presharedKeyBase64: presharedKeyBase64, keepalive: keepalive)
    }
}
