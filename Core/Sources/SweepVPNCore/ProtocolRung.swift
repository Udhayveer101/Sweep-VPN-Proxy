import Foundation

/// The shipping protocol ladder. Every WireGuard rung carries the *same*
/// unmodified WireGuard tunnel — the rungs differ only in how its datagrams are
/// carried across a hostile network, so nothing below rung 1 weakens the crypto
/// (vault 03-Transports-Obfuscation/Obfuscation-Is-Not-Security).
/// Order is preference order; lower rawValue = preferred.
public enum ProtocolRung: Int, CaseIterable, Codable, Sendable, Comparable {
    /// Everyday default: WireGuard on its native UDP port.
    case wireGuardUDP = 1
    /// Same tunnel on UDP/443 — beats naive "block non-standard UDP" filters.
    case wireGuardUDP443 = 2
    /// WireGuard datagrams inside QUIC on UDP/443. Looks like HTTP/3, and QUIC
    /// connection migration helps roaming.
    case wireGuardQUIC = 3
    /// WireGuard inside a real TLS 1.3 session on TCP/443 (Proton-Stealth class).
    /// Survives networks that drop all UDP and DPI that demands a TLS handshake.
    case wireGuardTLS = 4
    /// Shadowsocks-2022 (AEAD, BLAKE3) carrying WireGuard on TCP/443 — no
    /// plaintext handshake at all, so nothing to fingerprint or actively probe.
    case shadowsocks2022 = 5
    /// Kernel IKEv2/IPsec. No extension process, lowest battery, MOBIKE roaming.
    case ikev2 = 6
    /// Last resort: WireGuard framed on plain TCP/443, TCP-over-TCP accepted.
    case wireGuardTCP = 7
    /// OpenVPN over UDP. Unlike every rung above, this is *not* our WireGuard
    /// tunnel in a different envelope — it is a different protocol with different
    /// crypto, reachable on third-party relays (VPN Gate) whose keys we do not
    /// control. Ranked last because of that, never because it is slow.
    case openVPNUDP = 8
    /// OpenVPN over TCP, usually :443. Same caveat as `openVPNUDP`.
    case openVPNTCP = 9

    /// Rungs that carry our own WireGuard tunnel to a peer whose key we hold.
    /// Everything outside this set is a third-party relay: the operator can see
    /// plaintext where our own servers cannot.
    public var isOwnWireGuardTunnel: Bool { self != .openVPNUDP && self != .openVPNTCP }

    public static func < (a: ProtocolRung, b: ProtocolRung) -> Bool { a.rawValue < b.rawValue }

    /// Everything except IKEv2 runs inside the packet-tunnel extension.
    public var usesPacketTunnel: Bool { self != .ikev2 }

    public var isUDP: Bool {
        switch self {
        case .wireGuardUDP, .wireGuardUDP443, .wireGuardQUIC, .ikev2, .openVPNUDP: return true
        default: return false
        }
    }

    /// Rungs that survive a network where every UDP port is dropped.
    public var survivesUDPBlock: Bool { !isUDP }

    /// Rungs whose bytes on the wire are indistinguishable from ordinary web
    /// traffic to a passive observer.
    public var looksLikeWeb: Bool {
        self == .wireGuardQUIC || self == .wireGuardTLS || self == .shadowsocks2022
    }

    /// Only the WireGuard rungs can carry the ML-KEM-768 hybrid PSK; IKEv2 has
    /// no PQ story on Apple's stack.
    public var supportsHybridPQ: Bool { isOwnWireGuardTunnel && self != .ikev2 }

    /// Rough cost ranking used for battery-aware tie-breaks (1 = cheapest).
    public var overheadRank: Int {
        switch self {
        case .ikev2: return 1
        case .wireGuardUDP, .wireGuardUDP443: return 2
        case .wireGuardQUIC: return 3
        case .shadowsocks2022: return 4
        case .wireGuardTLS: return 5
        case .wireGuardTCP: return 6
        case .openVPNUDP: return 4
        case .openVPNTCP: return 6
        }
    }

    public var displayName: String {
        switch self {
        case .wireGuardUDP: return "WireGuard"
        case .wireGuardUDP443: return "WireGuard (UDP 443)"
        case .wireGuardQUIC: return "WireGuard over QUIC"
        case .wireGuardTLS: return "Stealth (TLS 443)"
        case .shadowsocks2022: return "Shadowsocks 2022"
        case .ikev2: return "IKEv2 (low power)"
        case .wireGuardTCP: return "WireGuard over TCP"
        case .openVPNUDP: return "OpenVPN (UDP)"
        case .openVPNTCP: return "OpenVPN (TCP)"
        }
    }

    public var shortName: String {
        switch self {
        case .wireGuardUDP: return "WG/UDP"
        case .wireGuardUDP443: return "WG/UDP 443"
        case .wireGuardQUIC: return "WG/QUIC"
        case .wireGuardTLS: return "WG/TLS"
        case .shadowsocks2022: return "SS2022"
        case .ikev2: return "IKEv2"
        case .wireGuardTCP: return "WG/TCP"
        case .openVPNUDP: return "OVPN/UDP"
        case .openVPNTCP: return "OVPN/TCP"
        }
    }
}

/// What the user picked in the UI. `automatic` is the default and the only
/// concept most users ever see (vault 11-UX/Protocol-Menu-Design).
public enum ProtocolPreference: Equatable, Hashable, Codable, Sendable {
    case automatic
    case fast                  // pin the cheapest UDP rungs
    case stealth               // only rungs that look like ordinary web traffic
    case lowPower              // kernel IKEv2
    case forced(ProtocolRung)  // power-user override

    /// Rungs the engine may use, in preference order.
    public func permittedRungs(enabledTiers: Set<ProtocolRung>) -> [ProtocolRung] {
        let all = ProtocolRung.allCases.filter(enabledTiers.contains)
        switch self {
        // Automatic walks our own tunnel only. An OpenVPN relay is somebody
        // else's machine terminating your plaintext, so it is never something
        // the ladder falls onto on its own — it takes an explicit choice.
        case .automatic: return all.filter(\.isOwnWireGuardTunnel)
        case .fast: return all.filter { $0 == .wireGuardUDP || $0 == .wireGuardUDP443 }
        case .stealth: return all.filter(\.looksLikeWeb)
        case .lowPower: return all.filter { $0 == .ikev2 }
        case .forced(let r): return all.filter { $0 == r }
        }
    }

    /// Overrides disable racing and voluntary switching entirely.
    public var allowsVoluntarySwitching: Bool { self == .automatic }

    public var displayName: String {
        switch self {
        case .automatic: return "Automatic"
        case .fast: return "Fast"
        case .stealth: return "Stealth"
        case .lowPower: return "Low power"
        case .forced(let r): return r.displayName
        }
    }
}
