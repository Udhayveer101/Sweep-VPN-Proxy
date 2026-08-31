import Foundation
import SweepVPNCore

/// Builds the server catalog that goes into a signed bundle.
///
///   sweep-catalog personal <config.json> <out.json>
///       Turn a small description of your own VPS fleet into a bundle.
///   sweep-catalog import-mullvad <out.json> [--limit N] [--country se,de]
///       Import Mullvad's *public* relay list (hostname, public key, ports).
///       These entries are marked `requiresAccount` — they only work once you
///       have registered this device's key with that operator. They are
///       included so the app has an extensive, real, measurable server list.
///   sweep-catalog merge <a.json> <b.json> ... <out.json>
///
/// The output is an unsigned ConfigBundle; sign it with `sweep-sign`.

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let encoder: JSONEncoder = {
    let e = ConfigVerifier.encoder()
    e.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
    return e
}()

/// Ports we ask the server side to listen on for each rung.
enum Ports {
    static let wireGuard: UInt16 = 51820
    static let wireGuardAlt: UInt16 = 443
    static let quic: UInt16 = 443
    static let tls: UInt16 = 443
    static let shadowsocks: UInt16 = 8443
    static let tcp: UInt16 = 8080
    static let ikev2: UInt16 = 500
}

/// Description of one machine you control.
struct PersonalServer: Codable {
    var id: String
    var name: String
    var countryCode: String
    var cityName: String?
    var provider: String?
    var host: String                 // IP literal
    var publicKey: String            // WireGuard server public key
    var tunnelAddress: String        // this device's address inside the tunnel
    var tunnelAddressV6: String?
    var dns: [String]
    var filteringDNS: [String]?
    var sni: String?                 // cover name for the TLS/QUIC rungs
    var shadowsocksKey: String?      // 32-byte base64 PSK for rung 5
    var rungs: [Int]?                // defaults to every rung the bridge serves
}

struct PersonalConfig: Codable {
    var minimumAppBuild: Int
    var validDays: Int
    var version: UInt64
    var servers: [PersonalServer]
}

func endpoints(for s: PersonalServer) -> [ServerEndpoint] {
    let wanted = Set(s.rungs?.compactMap(ProtocolRung.init(rawValue:)) ?? ProtocolRung.allCases)
    var result: [ServerEndpoint] = []
    for rung in ProtocolRung.allCases where wanted.contains(rung) {
        switch rung {
        case .wireGuardUDP:
            result.append(.init(host: s.host, port: Ports.wireGuard, rung: rung))
        case .wireGuardUDP443:
            result.append(.init(host: s.host, port: Ports.wireGuardAlt, rung: rung))
        case .wireGuardQUIC:
            result.append(.init(host: s.host, port: Ports.quic, rung: rung, sni: s.sni))
        case .wireGuardTLS:
            result.append(.init(host: s.host, port: Ports.tls, rung: rung, sni: s.sni))
        case .shadowsocks2022:
            guard let key = s.shadowsocksKey else { continue }
            result.append(.init(host: s.host, port: Ports.shadowsocks, rung: rung, secret: key))
        case .wireGuardTCP:
            result.append(.init(host: s.host, port: Ports.tcp, rung: rung))
        case .ikev2:
            result.append(.init(host: s.host, port: Ports.ikev2, rung: rung))
        }
    }
    return result
}

func bundle(from config: PersonalConfig) -> ConfigBundle {
    let now = Date()
    let servers = config.servers.map { s in
        Server(id: s.id, name: s.name, countryCode: s.countryCode.uppercased(),
               publicKey: s.publicKey, endpoints: endpoints(for: s),
               dnsServers: s.dns, filteringDNSServers: s.filteringDNS ?? [],
               ipv4Address: s.tunnelAddress, ipv6Address: s.tunnelAddressV6,
               provider: s.provider, cityName: s.cityName)
    }
    return ConfigBundle(version: config.version, issuedAt: now,
                        expiresAt: now.addingTimeInterval(Double(config.validDays) * 86_400),
                        minimumAppBuild: config.minimumAppBuild, servers: servers,
                        enabledRungs: ProtocolRung.allCases)
}

// MARK: - Mullvad public relay list

struct MullvadRelay: Decodable {
    var hostname: String
    var country_code: String
    var country_name: String
    var city_name: String
    var active: Bool
    var owned: Bool
    var provider: String
    var ipv4_addr_in: String
    var ipv6_addr_in: String?
    var pubkey: String
    var multihop_port: Int?
}

/// Fetch a URL synchronously. Kept explicit so the tool works the same whether
/// it is run by hand or from a build script.
func fetch(_ url: URL) throws -> Data {
    var result: Result<Data, Error>?
    let semaphore = DispatchSemaphore(value: 0)
    URLSession.shared.dataTask(with: url) { data, _, error in
        result = data.map { .success($0) } ?? .failure(error ?? URLError(.badServerResponse))
        semaphore.signal()
    }.resume()
    _ = semaphore.wait(timeout: .now() + 60)
    guard let result else { throw URLError(.timedOut) }
    return try result.get()
}

func importMullvad(limit: Int?, countries: Set<String>, from path: String?) throws -> [Server] {
    let data: Data
    if let path {
        data = try Data(contentsOf: URL(fileURLWithPath: path))
    } else {
        data = try fetch(URL(string: "https://api.mullvad.net/www/relays/wireguard/")!)
    }
    let relays = try JSONDecoder().decode([MullvadRelay].self, from: data)
    var servers = relays
        .filter(\.active)
        .filter { countries.isEmpty || countries.contains($0.country_code.lowercased()) }
        .map { relay -> Server in
            Server(id: relay.hostname, name: "\(relay.city_name), \(relay.country_name)",
                   countryCode: relay.country_code.uppercased(),
                   publicKey: relay.pubkey,
                   endpoints: [.init(host: relay.ipv4_addr_in, port: Ports.wireGuard, rung: .wireGuardUDP),
                               .init(host: relay.ipv4_addr_in, port: Ports.wireGuardAlt, rung: .wireGuardUDP443)],
                   dnsServers: ["10.64.0.1"],
                   ipv4Address: "10.64.0.2",
                   requiresAccount: true,
                   provider: relay.provider + (relay.owned ? " (operator-owned)" : ""),
                   cityName: relay.city_name)
        }
        .sorted { ($0.countryCode, $0.name) < ($1.countryCode, $1.name) }
    if let limit { servers = Array(servers.prefix(limit)) }
    return servers
}

// MARK: - Commands

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { die("usage: sweep-catalog personal|import-mullvad|merge …") }

do {
    switch command {
    case "personal":
        guard args.count == 3 else { die("usage: sweep-catalog personal <config.json> <out.json>") }
        let config = try JSONDecoder().decode(PersonalConfig.self,
                                              from: Data(contentsOf: URL(fileURLWithPath: args[1])))
        let out = bundle(from: config)
        try encoder.encode(out).write(to: URL(fileURLWithPath: args[2]), options: .atomic)
        print("wrote \(out.servers.count) server(s), \(out.servers.flatMap(\.endpoints).count) endpoints")

    case "import-mullvad":
        guard args.count >= 2 else { die("usage: sweep-catalog import-mullvad <out.json> [--limit N] [--country se,de] [--from relays.json]") }
        var limit: Int?
        var countries: Set<String> = []
        var from: String?
        var i = 2
        while i < args.count {
            switch args[i] {
            case "--limit": limit = Int(args[i + 1] ?? "")
            case "--country": countries = Set((args[i + 1] ?? "").split(separator: ",").map { $0.lowercased() })
            case "--from": from = args[i + 1]
            default: die("unknown flag \(args[i])")
            }
            i += 2
        }
        let servers = try importMullvad(limit: limit, countries: countries, from: from)
        let now = Date()
        let out = ConfigBundle(version: 1, issuedAt: now,
                               expiresAt: now.addingTimeInterval(30 * 86_400),
                               minimumAppBuild: 1, servers: servers,
                               enabledRungs: ProtocolRung.allCases)
        try encoder.encode(out).write(to: URL(fileURLWithPath: args[1]), options: .atomic)
        print("imported \(servers.count) relays across \(Set(servers.map(\.countryCode)).count) countries")
        print("NOTE: these are marked requiresAccount — they carry traffic only for a device key")
        print("      registered with that operator. Your own servers stay the default.")

    case "merge":
        guard args.count >= 3 else { die("usage: sweep-catalog merge <in.json>… <out.json>") }
        let inputs = args.dropFirst().dropLast()
        var servers: [Server] = []
        var seen = Set<ServerID>()
        var version: UInt64 = 1
        var minimumAppBuild = 1
        var expires = Date.distantFuture
        for path in inputs {
            let b = try ConfigVerifier.decoder().decode(ConfigBundle.self,
                                                        from: Data(contentsOf: URL(fileURLWithPath: path)))
            version = max(version, b.version)
            minimumAppBuild = max(minimumAppBuild, b.minimumAppBuild)
            expires = min(expires, b.expiresAt)
            for s in b.servers where seen.insert(s.id).inserted { servers.append(s) }
        }
        // Personal servers first: they are the ones that work without an account.
        servers.sort { !$0.requiresAccount && $1.requiresAccount }
        let out = ConfigBundle(version: version, issuedAt: Date(), expiresAt: expires,
                               minimumAppBuild: minimumAppBuild, servers: servers,
                               enabledRungs: ProtocolRung.allCases)
        try encoder.encode(out).write(to: URL(fileURLWithPath: args[args.count - 1]), options: .atomic)
        print("merged \(servers.count) servers (\(servers.filter { !$0.requiresAccount }.count) usable without an account)")

    default:
        die("unknown command \(command)")
    }
} catch {
    die("error: \(error)")
}
