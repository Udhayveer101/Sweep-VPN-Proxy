import Foundation
import SwiftUI
import SweepVPNCore

/// Pure mapping from tunnel state to what the user sees. Kept free of SwiftUI
/// types that need a view context so it can be unit-tested — state legibility
/// is a security control (vault 11-UX/Connection-State-And-Feedback).
public struct Presentation: Equatable, Sendable {
    public enum Tint: String, Sendable { case neutral, good, warning, danger }
    public enum Action: String, Sendable { case connect, disconnect, retry, openSettings, cancel }

    public var headline: String
    public var detail: String
    public var tint: Tint
    public var primaryAction: Action
    public var primaryActionTitle: String
    public var showsQuality: Bool
    public var voiceOver: String

    public static func make(state: TunnelState, serverName: String?, killSwitchArmed: Bool,
                            onDemandArmed: Bool, quality: Quality?) -> Presentation {
        switch state {
        case .disconnected:
            return .init(headline: "Not protected",
                         detail: killSwitchArmed ? "Kill switch is armed" : "Traffic uses this network directly",
                         tint: .neutral, primaryAction: .connect, primaryActionTitle: "Connect",
                         showsQuality: false, voiceOver: "Not protected. Double tap to connect.")
        case .onDemandArmed:
            return .init(headline: "Standing by",
                         detail: "Will connect automatically when any app sends traffic",
                         tint: .neutral, primaryAction: .connect, primaryActionTitle: "Connect now",
                         showsQuality: false, voiceOver: "Standing by. Will connect automatically.")
        case .connecting:
            return .init(headline: "Connecting…", detail: "Finding the best route",
                         tint: .neutral, primaryAction: .cancel, primaryActionTitle: "Cancel",
                         showsQuality: false, voiceOver: "Connecting.")
        case .handshaking:
            return .init(headline: "Connecting…", detail: "Verifying the server",
                         tint: .neutral, primaryAction: .cancel, primaryActionTitle: "Cancel",
                         showsQuality: false, voiceOver: "Verifying the server.")
        case .connected:
            return .init(headline: "Protected", detail: serverName ?? "Connected",
                         tint: .good, primaryAction: .disconnect, primaryActionTitle: "Disconnect",
                         showsQuality: true,
                         voiceOver: "Protected via \(serverName ?? "your server"). Double tap to disconnect.")
        case .degraded:
            return .init(headline: "Protected — weak connection",
                         detail: "Still encrypted. Quality is poor on this network.",
                         tint: .warning, primaryAction: .disconnect, primaryActionTitle: "Disconnect",
                         showsQuality: true, voiceOver: "Protected, but the connection is weak.")
        case .reasserting, .reconnecting:
            return .init(headline: "Reconnecting…",
                         detail: "Your traffic is paused until the tunnel is back — nothing is leaking.",
                         tint: .warning, primaryAction: .cancel, primaryActionTitle: "Turn off VPN",
                         showsQuality: false,
                         voiceOver: "Reconnecting. Traffic is blocked, not leaking.")
        case .killSwitchActive:
            return .init(headline: "Not connected — traffic blocked",
                         detail: "The kill switch is holding traffic. Nothing will load until you reconnect.",
                         tint: .danger, primaryAction: .retry, primaryActionTitle: "Retry",
                         showsQuality: false,
                         voiceOver: "Traffic blocked by the kill switch. Double tap to retry.")
        case .error(.notConfigured):
            // Not an incident: the app has simply never been given a server.
            // Saying "traffic blocked" here would cry wolf.
            return .init(headline: "Not set up yet",
                         detail: message(for: .notConfigured), tint: .neutral,
                         primaryAction: .openSettings, primaryActionTitle: "How to finish setup",
                         showsQuality: false, voiceOver: message(for: .notConfigured))
        case .error(let kind):
            return .init(headline: "Not connected — traffic blocked",
                         detail: message(for: kind), tint: .danger,
                         primaryAction: kind == .systemDenied ? .openSettings : .retry,
                         primaryActionTitle: kind == .systemDenied ? "Open Settings" : "Retry",
                         showsQuality: false, voiceOver: message(for: kind))
        }
    }

    /// Errors name a cause and an action — never a bare code.
    static func message(for kind: TunnelErrorKind) -> String {
        switch kind {
        case .notConfigured:
            return "Sweep has no server list yet. Add a signed configuration to finish setup."
        case .configurationInvalid:
            return "The signed configuration could not be verified, so the app refused to connect."
        case .noServersAvailable: return "No server in the signed list is reachable right now."
        case .allRungsFailed: return "This network blocked every connection method Sweep can use."
        case .authenticationFailed: return "The server did not accept this device's key."
        case .systemDenied: return "The VPN profile was removed. Re-enable it in Settings."
        case .internalFailure: return "The tunnel could not start. Try again."
        }
    }

    public enum Quality: String, Sendable, Equatable { case good, fair, weak

        /// Calm 3-state indicator from live RTT + loss — no graphs.
        public static func from(rttMs: Double, lossFraction: Double) -> Quality {
            if lossFraction > 0.03 || rttMs > 250 { return .weak }
            if lossFraction > 0.01 || rttMs > 120 { return .fair }
            return .good
        }
    }
}

public extension Presentation.Quality {
    /// Colour used for latency figures in the server list.
    var tint: Color {
        switch self {
        case .good: return .green
        case .fair: return .orange
        case .weak: return .red
        }
    }
}

public extension Presentation.Tint {
    var color: Color {
        switch self {
        case .neutral: return Color.secondary
        case .good: return Color.green
        case .warning: return Color.orange
        case .danger: return Color.red
        }
    }
}
