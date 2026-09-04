import Foundation

/// Decides whether a path update is roaming or just our own tunnel appearing.
///
/// `NWPathMonitor` fires on every routing change, including the ones the tunnel
/// causes by installing its own settings. Treating each of those as roaming and
/// re-handshaking is a reconnect storm: the reassert redials the relay, which
/// changes the path, which reasserts again — and because forwarding is gated
/// while reasserting, the tunnel carries nothing in between. Measured on the
/// 2026-09-04 journal, a session never held a route for more than about ten
/// seconds and no page ever finished loading.
///
/// The fix is to compare only the interfaces that are not ours. The caller
/// builds `signature` from the path's non-tunnel interfaces; identical
/// signatures mean the same underlying network, whatever the routing table did.
public struct RoamingDetector: Sendable, Equatable {
    public enum Decision: Sendable, Equatable {
        /// The network went away.
        case lost
        /// First update of this session — nothing to compare against yet.
        case first
        /// Same underlying network. Leave the tunnel alone.
        case unchanged
        /// Genuinely a different network. Re-handshake.
        case roamed(from: String, to: String)
    }

    private var last: String?

    public init(last: String? = nil) { self.last = last }

    public mutating func update(satisfied: Bool, signature: String) -> Decision {
        guard satisfied else {
            last = nil
            return .lost
        }
        let previous = last
        last = signature
        guard let previous else { return .first }
        return previous == signature ? .unchanged : .roamed(from: previous, to: signature)
    }
}
