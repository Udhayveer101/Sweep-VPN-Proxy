import Foundation

public typealias ServerID = String

public struct ServerEndpoint: Codable, Sendable, Equatable, Hashable {
    public var host: String          // IP literal preferred — no DNS at connect time
    public var port: UInt16
    public var rung: ProtocolRung
    public init(host: String, port: UInt16, rung: ProtocolRung) {
        self.host = host; self.port = port; self.rung = rung
    }
}

public struct Server: Codable, Sendable, Equatable, Identifiable {
    public var id: ServerID
    public var name: String
    public var countryCode: String
    public var jurisdictionPenalty: Double   // 0 = fine, higher = worse; .infinity = hard avoid
    public var publicKey: String             // WireGuard peer public key (base64)
    public var endpoints: [ServerEndpoint]
    public var dnsServers: [String]          // in-tunnel resolver addresses
    public var ipv4Address: String           // tunnel address assigned to this device
    public var ipv6Address: String?
    public var load: Double                  // 0…1, from the signed bundle
    public var reliability: Double           // 0…1, on-device rolling measure

    public init(id: ServerID, name: String, countryCode: String, jurisdictionPenalty: Double = 0,
                publicKey: String, endpoints: [ServerEndpoint], dnsServers: [String],
                ipv4Address: String, ipv6Address: String? = nil,
                load: Double = 0, reliability: Double = 1) {
        self.id = id; self.name = name; self.countryCode = countryCode
        self.jurisdictionPenalty = jurisdictionPenalty; self.publicKey = publicKey
        self.endpoints = endpoints; self.dnsServers = dnsServers
        self.ipv4Address = ipv4Address; self.ipv6Address = ipv6Address
        self.load = load; self.reliability = reliability
    }

    public func supports(_ rung: ProtocolRung) -> Bool { endpoints.contains { $0.rung == rung } }
}

public struct ServerProbe: Sendable, Equatable {
    public var rttMs: Double
    public var lossFraction: Double
    public var jitterMs: Double
    public init(rttMs: Double, lossFraction: Double, jitterMs: Double = 0) {
        self.rttMs = rttMs; self.lossFraction = lossFraction; self.jitterMs = jitterMs
    }
}

/// score = 1.0·rtt + 8.0·loss%·100 + 0.5·jitter + 0.4·load·100
///       + 0.6·(1−reliability)·100 + 1.0·jurisdiction   (lower is better)
public enum ServerScoring {
    public static let maxLoss = 0.05
    public static let maxRttMs = 800.0

    public static func score(_ s: Server, _ p: ServerProbe) -> Double {
        1.0 * p.rttMs
            + 8.0 * (p.lossFraction * 100)               // 8 points per percent of loss
            + 0.5 * p.jitterMs
            + 0.4 * s.load * 100
            + 0.6 * (1 - s.reliability) * 100
            + 1.0 * s.jurisdictionPenalty
    }

    /// Hard gates run before scoring — a gated server is never selected.
    public static func isEligible(_ s: Server, _ p: ServerProbe, rung: ProtocolRung) -> Bool {
        guard s.supports(rung) else { return false }
        guard s.jurisdictionPenalty.isFinite else { return false }
        guard p.lossFraction <= maxLoss, p.rttMs <= maxRttMs else { return false }
        return true
    }

    public static func best(from candidates: [(Server, ServerProbe)], rung: ProtocolRung) -> Server? {
        candidates
            .filter { isEligible($0.0, $0.1, rung: rung) }
            .min { score($0.0, $0.1) < score($1.0, $1.1) }?.0
    }

    /// Move only for a real gain, and only after the server dwell has elapsed.
    public static func shouldSwitch(current: (Server, ServerProbe), rival: (Server, ServerProbe),
                                    connectedSince: Date, now: Date,
                                    constants: AutoModeConstants = .init()) -> Bool {
        guard now.timeIntervalSince(connectedSince) >= constants.minServerDwell else { return false }
        guard current.1.rttMs - rival.1.rttMs > constants.serverSwitchMinGainMs else { return false }
        return score(rival.0, rival.1) < score(current.0, current.1)
    }
}
