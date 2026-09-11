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
        case .openVPNUDP, .openVPNTCP:
            continue   // VPN Gate relays, never a personal server rung
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

// MARK: - WireGuard .conf import (Proton VPN and anything else that emits one)

/// Parse a standard WireGuard config. Operators like Proton hand these out per
/// server, each with the device key they registered, so the key travels with
/// the server rather than being generated on the device.
func importWireGuardConf(_ path: String) throws -> Server {
    let text = try String(contentsOfFile: path, encoding: .utf8)
    var section = ""
    var f: [String: String] = [:]
    var peerName: String?

    for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.hasPrefix("[") {
            section = line.lowercased()
            continue
        }
        // Proton names the server in a comment above the peer: "# NL-FREE#1".
        if line.hasPrefix("#") {
            let comment = line.dropFirst().trimmingCharacters(in: .whitespaces)
            if section.contains("peer"), peerName == nil, !comment.isEmpty,
               !comment.lowercased().contains("=") {
                peerName = comment
            }
            continue
        }
        guard let eq = line.firstIndex(of: "=") else { continue }
        let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
        let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        f[section.contains("peer") ? "peer.\(key)" : "iface.\(key)"] = value
    }

    guard let priv = f["iface.privatekey"], !priv.isEmpty else {
        throw NSError(domain: "wg", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "\(path): no PrivateKey in [Interface]"])
    }
    guard let pub = f["peer.publickey"], let endpoint = f["peer.endpoint"] else {
        throw NSError(domain: "wg", code: 2, userInfo: [NSLocalizedDescriptionKey:
            "\(path): no PublicKey/Endpoint in [Peer]"])
    }
    // Endpoint is host:port; an IPv6 literal is bracketed.
    guard let colon = endpoint.lastIndex(of: ":"),
          let port = UInt16(endpoint[endpoint.index(after: colon)...]) else {
        throw NSError(domain: "wg", code: 3, userInfo: [NSLocalizedDescriptionKey:
            "\(path): could not parse Endpoint '\(endpoint)'"])
    }
    let host = String(endpoint[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))

    let addresses = (f["iface.address"] ?? "").split(separator: ",").map {
        $0.trimmingCharacters(in: .whitespaces)
    }
    let v4 = addresses.first { !$0.contains(":") }?.split(separator: "/").first.map(String.init)
    let v6 = addresses.first { $0.contains(":") }?.split(separator: "/").first.map(String.init)
    let dns = (f["iface.dns"] ?? "").split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

    let name = peerName ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
    // Proton encodes the country in the peer name ("NL-FREE#1", "JP#12").
    let cc = String(name.prefix(2)).uppercased()
    let country = cc.allSatisfy { $0.isLetter } ? cc : "XX"

    return Server(id: name, name: name, countryCode: country, publicKey: pub,
                  endpoints: [.init(host: host, port: port, rung: .wireGuardUDP)],
                  dnsServers: dns.isEmpty ? ["1.1.1.1"] : dns,
                  ipv4Address: v4 ?? "10.2.0.2", ipv6Address: v6,
                  provider: "Proton VPN", cityName: nil,
                  devicePrivateKey: priv)
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

    case "import-wireguard":
        guard args.count >= 3 else {
            die("usage: sweep-catalog import-wireguard <out.json> <config.conf>…")
        }
        let confs = Array(args.dropFirst(2))
        var servers: [Server] = []
        var seen = Set<ServerID>()
        for path in confs {
            let s = try importWireGuardConf(path)
            guard seen.insert(s.id).inserted else {
                print("skipping duplicate \(s.id)"); continue
            }
            servers.append(s)
        }
        guard !servers.isEmpty else { die("no usable configs") }
        let now = Date()
        let out = ConfigBundle(version: UInt64(now.timeIntervalSince1970), issuedAt: now,
                               expiresAt: now.addingTimeInterval(90 * 86_400),
                               minimumAppBuild: 1, servers: servers,
                               enabledRungs: ProtocolRung.allCases)
        try encoder.encode(out).write(to: URL(fileURLWithPath: args[1]), options: .atomic)
        print("imported \(servers.count) server(s) across \(Set(servers.map(\.countryCode)).count) countries")
        print("NOTE: these carry per-config device keys — sign with --local-only and never host the bundle.")

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
