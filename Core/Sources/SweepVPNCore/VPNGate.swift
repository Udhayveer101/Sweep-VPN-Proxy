import Foundation

/// Parser for the VPN Gate public relay list (University of Tsukuba).
///
/// What this is *not*: VPN Gate relays are volunteer-run OpenVPN servers whose
/// keys nobody here controls. The operator terminates your traffic in
/// plaintext and can log it — several of them say so outright in the `LogType`
/// column. That is a categorically weaker trust model than the WireGuard rungs,
/// which talk only to peers whose key is ours. Everything in this file is built
/// to keep that difference visible rather than to paper over it: relays land on
/// the OpenVPN rungs, which `ProtocolPreference.automatic` refuses to select.
///
/// Wire format is the CSV at `/api/iphone/`:
///
///     *vpn_servers
///     #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,
///     Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
///     public-vpn-255,219.100.37.224,2834781,10,599789341,Japan,JP,…,<base64 .ovpn>
///     *
///
/// VPN Gate substitutes `_` for commas inside the free-text columns, so a plain
/// comma split is safe as long as the base64 profile is taken from the end.
public enum VPNGate {

    /// One row of the published list, before it becomes a `Server`.
    public struct Relay: Sendable, Equatable {
        public var hostName: String
        public var ip: String
        public var countryCode: String
        public var countryName: String
        /// Ping in ms as *advertised by the relay*. Never trusted for ranking —
        /// we measure ourselves — but useful to order a list we have not
        /// probed yet.
        public var advertisedPingMs: Double?
        /// Advertised line speed in bits/sec.
        public var speedBps: Double?
        public var sessions: Int?
        /// How long the relay has been up, as the operator's own daemon reports
        /// it (milliseconds). A weak signal, but the only one about *durability*
        /// the list carries at all, and durability is what a volunteer relay is
        /// short of.
        public var uptimeMs: Double?
        /// Operator's own declaration of what they retain. Free text, and
        /// unverifiable — shown to the user as the operator's claim, not as
        /// a fact.
        public var logType: String?
        public var operatorName: String?
        /// The full `.ovpn` profile, decoded.
        public var openVPNProfile: String
        /// Transport and port read out of the profile itself, which is the only
        /// authoritative source for them.
        public var proto: Proto
        public var port: UInt16

        public enum Proto: String, Sendable, Equatable {
            case udp, tcp
            public var rung: ProtocolRung { self == .udp ? .openVPNUDP : .openVPNTCP }
        }
    }

    // MARK: - CSV

    public enum ParseError: Error, Equatable {
        case noRows
    }

    /// Parse the published CSV. Malformed rows are skipped rather than failing
    /// the batch: the list is third-party input and one bad row should not cost
    /// the user the other three hundred.
    public static func parseCSV(_ text: String) -> [Relay] {
        var relays: [Relay] = []
        var columns: [String: Int] = [:]

        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if line.hasPrefix("*") { continue }          // *vpn_servers / trailing *
            if line.hasPrefix("#") {                     // header
                let names = line.dropFirst().components(separatedBy: ",")
                columns = Dictionary(uniqueKeysWithValues:
                    names.enumerated().map { ($0.element.trimmingCharacters(in: .whitespaces), $0.offset) })
                continue
            }
            guard !columns.isEmpty else { continue }
            if let relay = parseRow(line, columns: columns) { relays.append(relay) }
        }
        return relays
    }

    private static func parseRow(_ line: String, columns: [String: Int]) -> Relay? {
        let fields = line.components(separatedBy: ",")
        func field(_ name: String) -> String? {
            guard let i = columns[name], i < fields.count else { return nil }
            let v = fields[i].trimmingCharacters(in: .whitespaces)
            return v.isEmpty ? nil : v
        }

        guard let ip = field("IP"), !ip.isEmpty else { return nil }
        // The profile is always the final column, so it survives extra commas
        // in any free-text field ahead of it.
        guard let encoded = fields.last?.trimmingCharacters(in: .whitespaces),
              let data = Data(base64Encoded: encoded, options: .ignoreUnknownCharacters),
              let profile = String(data: data, encoding: .utf8),
              let wire = parseProfile(profile)
        else { return nil }

        return Relay(
            hostName: field("HostName") ?? ip,
            ip: ip,
            countryCode: (field("CountryShort") ?? "ZZ").uppercased(),
            countryName: field("CountryLong") ?? "Unknown",
            advertisedPingMs: field("Ping").flatMap(Double.init),
            speedBps: field("Speed").flatMap(Double.init),
            sessions: field("NumVpnSessions").flatMap(Int.init),
            uptimeMs: field("Uptime").flatMap(Double.init),
            logType: field("LogType"),
            operatorName: field("Operator"),
            openVPNProfile: profile,
            proto: wire.proto,
            port: wire.port)
    }

    // MARK: - .ovpn

    /// Pull the transport and port out of a profile. We read `remote` and
    /// `proto` rather than trusting the CSV, because the profile is what an
    /// OpenVPN client would actually dial.
    static func parseProfile(_ profile: String) -> (proto: Relay.Proto, port: UInt16)? {
        var proto: Relay.Proto?
        var port: UInt16?

        for raw in profile.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard let directive = parts.first?.lowercased() else { continue }

            switch directive {
            case "proto":
                // "tcp-client" / "tcp4" all mean TCP here.
                guard parts.count >= 2 else { continue }
                proto = parts[1].lowercased().hasPrefix("tcp") ? .tcp : .udp
            case "remote":
                // remote <host> <port> [proto]
                guard parts.count >= 3, let p = UInt16(parts[2]) else { continue }
                port = p
                if parts.count >= 4 { proto = parts[3].lowercased().hasPrefix("tcp") ? .tcp : .udp }
            default:
                continue
            }
        }
        guard let proto, let port else { return nil }
        return (proto, port)
    }

    // MARK: - Mapping into the catalog

    /// Jurisdictions where the relay operator sits under a regime with routine
    /// interception powers. This is a nudge in the ranking, not a block — the
    /// user picks their own server, and a relay is never auto-selected anyway.
    static func jurisdictionPenalty(_ countryCode: String) -> Double {
        switch countryCode.uppercased() {
        case "RU", "CN", "IR", "BY", "KP": return 60
        case "VN", "KZ", "TR", "AE", "SA": return 25
        default: return 0
        }
    }

    /// Turn relays into catalog servers.
    ///
    /// `load` is used as the pre-measurement ordering key (`ServerCatalog`
    /// orders unprobed servers by it), so we seed it from advertised speed:
    /// a fat, idle line sorts above a saturated one until our own RTT probe
    /// replaces the guess entirely.
    public static func servers(from relays: [Relay]) -> [Server] {
        // 1 Gbps is a generous ceiling for a volunteer line; above it the
        // advertised number stops meaning anything useful.
        let speedCeiling = 1_000_000_000.0
        return relays.map { r in
            let normalizedSpeed = min((r.speedBps ?? 0) / speedCeiling, 1)
            // A relay that has been up six hours has shown more than one that
            // appeared ten minutes ago. Deliberately a nudge, floored at 0.5 so
            // it can never outweigh a measured RTT — and it is replaced outright
            // by `RelayStabilityStore` as soon as we have held a session on it.
            let uptimeHours = (r.uptimeMs ?? 0) / 3_600_000
            let seededReliability = max(0.5, min(1, uptimeHours / 6))
            let endpoint = ServerEndpoint(host: r.ip, port: r.port, rung: r.proto.rung,
                                          openVPNProfile: r.openVPNProfile)
            return Server(
                id: "vpngate:\(r.ip):\(r.port):\(r.proto.rawValue)",
                name: r.hostName,
                countryCode: r.countryCode,
                jurisdictionPenalty: jurisdictionPenalty(r.countryCode),
                // Not a WireGuard peer: there is no key of ours on the far end.
                publicKey: "",
                endpoints: [endpoint],
                // OpenVPN pushes its own resolver and tunnel address at connect
                // time; nothing here is known in advance.
                dnsServers: [],
                ipv4Address: "",
                load: 1 - normalizedSpeed,
                reliability: seededReliability,
                requiresAccount: false,
                provider: r.operatorName,
                cityName: r.countryName,
                logPolicy: r.logType)
        }
    }

    /// Convenience: CSV text straight to catalog servers.
    public static func servers(fromCSV text: String) -> [Server] {
        servers(from: parseCSV(text))
    }
}
