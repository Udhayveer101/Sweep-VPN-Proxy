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
}

public enum DegradeReason: String, Equatable, Sendable, Codable {
    case highLoss, highLatency, handshakeFlapping, rungDowngraded
}

public enum TunnelErrorKind: String, Equatable, Sendable, Codable {
    case notConfigured             // no pinned key / no server list yet -> setup, not an attack
    case configurationInvalid      // signature / version / expiry failure -> fail closed
    case noServersAvailable
    case allRungsFailed
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
