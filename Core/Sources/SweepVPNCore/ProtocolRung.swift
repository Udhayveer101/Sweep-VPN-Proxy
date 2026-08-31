import Foundation

/// The shipping protocol ladder (vault 12-Synthesis/Recommended-Protocol-Stack).
/// Order is the preference order; lower rawValue = preferred.
public enum ProtocolRung: Int, CaseIterable, Codable, Sendable, Comparable {
    case wireGuardUDP = 1        // native port then UDP/443 — everyday default
    case wireGuardQUIC = 2       // TLS-wrapped QUIC on UDP/443 (Tier 2 gated)
    case stealthTCP443 = 3       // REALITY / Shadowsocks-2022 over TCP/443 (Tier 2)
    case ikev2 = 4               // kernel NEVPNProtocolIKEv2 — low-power / no-dependency
    case wireGuardTCP = 5        // last resort, TCP-over-TCP accepted

    public static func < (a: ProtocolRung, b: ProtocolRung) -> Bool { a.rawValue < b.rawValue }

    public var usesPacketTunnel: Bool { self != .ikev2 }
    public var isUDP: Bool { self == .wireGuardUDP || self == .wireGuardQUIC }
    /// Only rungs 1–2 carry the ML-KEM-768 hybrid PSK.
    public var supportsHybridPQ: Bool { self == .wireGuardUDP || self == .wireGuardQUIC }

    public var displayName: String {
        switch self {
        case .wireGuardUDP: return "WireGuard"
        case .wireGuardQUIC: return "WireGuard over QUIC"
        case .stealthTCP443: return "Stealth (TLS 443)"
        case .ikev2: return "IKEv2 (low power)"
        case .wireGuardTCP: return "WireGuard over TCP"
        }
    }
}

/// What the user picked in the UI. `automatic` is the default and the only
/// concept most users see (vault 11-UX/Protocol-Menu-Design).
public enum ProtocolPreference: Equatable, Codable, Sendable {
    case automatic
    case fast                  // pin rung 1
    case stealth               // start at rung 3
    case forced(ProtocolRung)  // power user override

    /// Rungs the engine may use, in preference order.
    public func permittedRungs(enabledTiers: Set<ProtocolRung>) -> [ProtocolRung] {
        let all = ProtocolRung.allCases.filter(enabledTiers.contains)
        switch self {
        case .automatic: return all
        case .fast: return all.filter { $0 == .wireGuardUDP }
        case .stealth: return all.filter { $0 >= .stealthTCP443 }
        case .forced(let r): return all.filter { $0 == r }
        }
    }

    /// Overrides disable racing and voluntary switching entirely.
    public var allowsVoluntarySwitching: Bool { self == .automatic }
}
