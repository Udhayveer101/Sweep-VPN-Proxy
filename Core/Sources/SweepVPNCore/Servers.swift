import Foundation

public typealias ServerID = String

public struct ServerEndpoint: Codable, Sendable, Equatable, Hashable {
    public var host: String          // IP literal preferred — no DNS at connect time
    public var port: UInt16
    public var rung: ProtocolRung
    /// Server name to present in the TLS/QUIC handshake for the web-shaped
    /// rungs. A plausible cover name is what makes the flow look ordinary.
    public var sni: String?
    /// Base64 credential the rung needs (the Shadowsocks-2022 PSK). Carried in
    /// the *signed* bundle and stored only in the Keychain.
    public var secret: String?

    public init(host: String, port: UInt16, rung: ProtocolRung,
                sni: String? = nil, secret: String? = nil) {
        self.host = host; self.port = port; self.rung = rung
        self.sni = sni; self.secret = secret
    }

    public var secretData: Data? { secret.flatMap { Data(base64Encoded: $0) } }
}

public struct Server: Codable, Sendable, Equatable, Identifiable {
    public var id: ServerID
    public var name: String
    public var countryCode: String
    public var jurisdictionPenalty: Double   // 0 = fine, higher = worse; .infinity = hard avoid
    public var publicKey: String             // WireGuard peer public key (base64)
    public var endpoints: [ServerEndpoint]
    public var dnsServers: [String]          // in-tunnel resolver addresses
    /// Optional second resolver on the same host that applies blocklists.
    public var filteringDNSServers: [String]
    public var ipv4Address: String           // tunnel address assigned to this device
    public var ipv6Address: String?
    public var load: Double                  // 0…1, from the signed bundle
    public var reliability: Double           // 0…1, on-device rolling measure
    /// True for relays that need an operator account/registered device key
    /// (e.g. an imported public relay list). The UI must not pretend these are
    /// usable before the user has supplied credentials.
    public var requiresAccount: Bool
    /// Server operator, shown so the user knows whose hardware they are on.
    public var provider: String?
    public var cityName: String?

    public init(id: ServerID, name: String, countryCode: String, jurisdictionPenalty: Double = 0,
                publicKey: String, endpoints: [ServerEndpoint], dnsServers: [String],
                filteringDNSServers: [String] = [],
                ipv4Address: String, ipv6Address: String? = nil,
                load: Double = 0, reliability: Double = 1,
                requiresAccount: Bool = false, provider: String? = nil,
                cityName: String? = nil) {
        self.id = id; self.name = name; self.countryCode = countryCode
        self.jurisdictionPenalty = jurisdictionPenalty; self.publicKey = publicKey
        self.endpoints = endpoints; self.dnsServers = dnsServers
        self.filteringDNSServers = filteringDNSServers
        self.ipv4Address = ipv4Address; self.ipv6Address = ipv6Address
        self.load = load; self.reliability = reliability
        self.requiresAccount = requiresAccount; self.provider = provider
        self.cityName = cityName
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

// MARK: - Catalog

/// One row of the server list as the UI shows it.
public enum ServerListEntry: Equatable, Sendable, Identifiable {
    /// Row 1: "Automatic" — connects to whatever is measured fastest right now.
    case automatic(fastest: Server?)
    /// Row 2: the fastest concrete server, pinned so it is always one tap away.
    case fastest(Server, ServerProbe?)
    /// Rows 3+: everything else, fastest to slowest.
    case server(Server, ServerProbe?)

    public var id: String {
        switch self {
        case .automatic: return "__automatic__"
        case .fastest(let s, _): return "fastest:" + s.id
        case .server(let s, _): return s.id
        }
    }

    public var server: Server? {
        switch self {
        case .automatic(let s): return s
        case .fastest(let s, _), .server(let s, _): return s
        }
    }

    public var probe: ServerProbe? {
        switch self {
        case .automatic: return nil
        case .fastest(_, let p), .server(_, let p): return p
        }
    }
}

/// Holds every known server plus the latest measurements, and produces the
/// ordered list the UI renders. Ordering rules (product requirement):
///   row 1 = Automatic (auto-connects to the fastest server),
///   row 2 = the fastest server, re-evaluated on every measurement,
///   rows 3+ = the rest, fastest → slowest, unmeasured last.
public struct ServerCatalog: Sendable, Equatable {
    public private(set) var servers: [Server]
    public private(set) var probes: [ServerID: ServerProbe]
    /// Rung the ranking is for — a server that cannot serve the active rung is
    /// ineligible however fast it pings.
    public var rung: ProtocolRung

    public init(servers: [Server] = [], probes: [ServerID: ServerProbe] = [:],
                rung: ProtocolRung = .wireGuardUDP) {
        self.servers = servers
        self.probes = probes
        self.rung = rung
    }

    public mutating func replaceServers(_ servers: [Server]) {
        self.servers = servers
        probes = probes.filter { id, _ in servers.contains { $0.id == id } }
    }

    public mutating func record(_ probe: ServerProbe, for id: ServerID) {
        probes[id] = probe
    }

    /// Every server that could actually be used right now, best first.
    public func ranked(includeAccountRequired: Bool = true) -> [(Server, ServerProbe?)] {
        let usable = servers.filter { server in
            (includeAccountRequired || !server.requiresAccount) && server.supports(rung)
        }
        let measured = usable.compactMap { s -> (Server, ServerProbe)? in
            guard let p = probes[s.id], ServerScoring.isEligible(s, p, rung: rung) else { return nil }
            return (s, p)
        }.sorted { ServerScoring.score($0.0, $0.1) < ServerScoring.score($1.0, $1.1) }

        let measuredIDs = Set(measured.map(\.0.id))
        // Unmeasured servers keep a stable, predictable order behind the measured
        // ones — lower advertised load first, then name.
        let unmeasured = usable.filter { !measuredIDs.contains($0.id) }
            .sorted { ($0.load, $0.name) < ($1.load, $1.name) }

        return measured.map { ($0.0, Optional($0.1)) } + unmeasured.map { ($0, nil) }
    }

    /// The server "Automatic" would pick right now.
    public func fastest(includeAccountRequired: Bool = true) -> Server? {
        ranked(includeAccountRequired: includeAccountRequired).first?.0
    }

    /// The rows the UI renders, in order.
    public func listEntries(includeAccountRequired: Bool = true) -> [ServerListEntry] {
        let ranked = self.ranked(includeAccountRequired: includeAccountRequired)
        guard let best = ranked.first else { return [.automatic(fastest: nil)] }
        return [.automatic(fastest: best.0), .fastest(best.0, best.1)]
            + ranked.dropFirst().map { ServerListEntry.server($0.0, $0.1) }
    }

    /// The ranked list in a form that crosses the app/extension boundary.
    public func rankedSnapshot(includeAccountRequired: Bool = true) -> [RankedServer] {
        ranked(includeAccountRequired: includeAccountRequired).map {
            RankedServer(server: $0.0, rttMs: $0.1?.rttMs, lossFraction: $0.1?.lossFraction)
        }
    }

    /// Which servers to probe next: the top few by cached score plus anything
    /// never measured, so the list converges without pinging hundreds of hosts
    /// (vault 07-Performance/Server-Selection-Scoring).
    public func probeTargets(limit: Int = 5, includeAccountRequired: Bool = true) -> [Server] {
        let ranked = self.ranked(includeAccountRequired: includeAccountRequired)
        let top = ranked.prefix(limit).map(\.0)
        let neverMeasured = ranked.filter { probes[$0.0.id] == nil }.prefix(limit).map(\.0)
        var seen = Set<ServerID>()
        return (top + neverMeasured).filter { seen.insert($0.id).inserted }
    }
}
