import Foundation

/// Explicit finite state for the tunnel. Authoritative copy lives in the
/// packet-tunnel provider; the app holds a mirrored copy fed over IPC.
/// UI is a pure function of this value (see vault 11-UX/Connection-State-And-Feedback).
public enum TunnelState: Equatable, Sendable, Codable {
    case disconnected
    case onDemandArmed
    case connecting(rung: ProtocolRung)
    case handshaking(rung: ProtocolRung)
    case connected(rung: ProtocolRung, server: ServerID)
    /// The system reports our tunnel up, but the provider has not yet answered
    /// over IPC, so we do not know the rung or the server. Never guess them:
    /// a fabricated "Protected via X on WireGuard" is a security claim we
    /// cannot substantiate. Forwarding is not asserted in this state.
    case verifying
    case reasserting          // network changed, forwarding suspended
    case reconnecting(attempt: Int)
    case degraded(rung: ProtocolRung, reason: DegradeReason)
    case killSwitchActive     // traffic blocked on purpose
    case error(TunnelErrorKind)

    /// True when the tunnel is authenticated and may forward user packets.
    /// Everything else must be treated as "blocked", never "open".
    public var forwardingAllowed: Bool {
        switch self {
        case .connected, .degraded: return true
        default: return false
        }
    }

    /// Whether protected traffic is currently blackholed (fail-closed posture).
    public var isBlocking: Bool { !forwardingAllowed }

    /// Short name for the journal. Carries the associated values, because
    /// "connecting" and "connecting on a different rung than last time" are the
    /// two readings a stalled connect has to be told apart by.
    public var logLabel: String {
        switch self {
        case .disconnected:                    return "disconnected"
        case .onDemandArmed:                   return "onDemandArmed"
        case .connecting(let r):               return "connecting(\(r.rawValue))"
        case .handshaking(let r):              return "handshaking(\(r.rawValue))"
        case .connected(let r, let s):         return "connected(\(r.rawValue), \(s))"
        case .verifying:                       return "verifying"
        case .reasserting:                     return "reasserting"
        case .reconnecting(let attempt):       return "reconnecting(attempt \(attempt))"
        case .degraded(let r, let why):        return "degraded(\(r.rawValue), \(why.rawValue))"
        case .killSwitchActive:                return "killSwitchActive"
        case .error(let kind):                 return "error(\(kind.rawValue))"
        }
    }

    /// States that mean the user is not protected *and* something went wrong,
    /// as opposed to simply being off. Used to pick a log level.
    public var isFailure: Bool {
        switch self {
        case .error, .killSwitchActive: return true
        default: return false
        }
    }
}

public enum DegradeReason: String, Equatable, Sendable, Codable {
    case highLoss, highLatency, handshakeFlapping, rungDowngraded
}

public enum TunnelErrorKind: String, Equatable, Sendable, Codable {
    case notConfigured             // no pinned key / no server list yet -> setup, not an attack
    case configurationInvalid      // signature / version / expiry failure -> fail closed
    case noServersAvailable
    case allRungsFailed
    case workerUnavailable        // the WSS Worker is failing; no relay is at fault
    case authenticationFailed
    case systemDenied               // user removed VPN profile / NE permission
    case internalFailure
}

/// Records every transition so the kill-switch posture is auditable in one place.
public struct StateMachine: Sendable {
    public private(set) var state: TunnelState = .disconnected
    private let log: @Sendable (TunnelState, TunnelState) -> Void

    public init(log: @escaping @Sendable (TunnelState, TunnelState) -> Void = { _, _ in }) {
        self.log = log
    }

    /// Returns true if the transition was legal and applied.
    @discardableResult
    public mutating func transition(to next: TunnelState) -> Bool {
        guard StateMachine.isLegal(from: state, to: next) else { return false }
        let old = state
        state = next
        log(old, next)
        return true
    }

    static func isLegal(from: TunnelState, to: TunnelState) -> Bool {
        if from == to { return true }
        switch (from, to) {
        // Any state may fail closed or be torn down.
        case (_, .killSwitchActive), (_, .error), (_, .disconnected), (_, .onDemandArmed):
            return true
        case (.disconnected, .connecting), (.onDemandArmed, .connecting):
            return true
        case (.connecting, .handshaking), (.connecting, .reconnecting):
            return true
        case (.handshaking, .connected), (.handshaking, .reconnecting), (.handshaking, .connecting):
            return true
        case (.connected, .reasserting), (.connected, .degraded), (.connected, .reconnecting):
            return true
        case (.degraded, .connected), (.degraded, .reconnecting), (.degraded, .reasserting):
            return true
        case (.reasserting, .handshaking), (.reasserting, .connecting), (.reasserting, .reconnecting),
             (.reasserting, .connected):
            return true
        case (.reconnecting, .connecting), (.reconnecting, .handshaking), (.reconnecting, .reconnecting):
            return true
        default:
            return false
        }
    }
}
