import Foundation
import SweepVPNCore

/// Downloads the VPN Gate public relay list and caches it on disk.
///
/// # Why this does not go through `ConfigStore`
///
/// Everything in the signed bundle is vouched for by an Ed25519 key held on the
/// user's own Mac: `ConfigStore` refuses anything that key did not sign. VPN
/// Gate's list cannot be signed by that key — it is a third party's file,
/// fetched over the network, and nobody here can vouch for a single row of it.
///
/// Running it through the same store would mean either weakening the verifier
/// or re-signing attacker-controlled input with the user's own key, and both
/// destroy the property the signed path exists for. So relays live in their own
/// cache, are marked as third-party in the catalog, and are reachable only on
/// the OpenVPN rungs that `ProtocolPreference.automatic` will not select. The
/// worst a poisoned list can do is offer relays the user must still pick by
/// hand — it can never displace a signed server or change app policy.
public final class VPNGateFetcher: Sendable {

    public enum FetchError: Error, Equatable {
        /// Every configured source failed. Carries the last transport status
        /// so the UI can tell "you are offline" from "your network blocks it".
        case allSourcesFailed(lastStatus: Int?)
        case emptyList
    }

    /// Where to look, in order. The official endpoint is first; it is also the
    /// one most likely to be blocked, because filtering products categorise the
    /// domain (an Indian residential ISP returns a 403 block page for it).
    ///
    /// `custom` exists for exactly that case: point it at a small proxy you run
    /// — a Cloudflare Worker that fetches the CSV and returns it is ~15 lines —
    /// and the app reaches the list from a domain no category filter knows.
    public static let officialSources: [URL] = [
        URL(string: "https://www.vpngate.net/api/iphone/")!,
        URL(string: "http://www.vpngate.net/api/iphone/")!,
    ]

    private let sources: [URL]
    private let session: URLSession
    private let cacheURL: URL?

    public init(customSource: URL? = nil,
                session: URLSession = .shared,
                cacheURL: URL? = VPNGateFetcher.defaultCacheURL()) {
        // A user-supplied source is tried first: they configured it because the
        // official one does not work where they are.
        self.sources = (customSource.map { [$0] } ?? []) + VPNGateFetcher.officialSources
        self.session = session
        self.cacheURL = cacheURL
    }

    // MARK: - Fetching

    /// Try each source until one returns a list that parses. On total failure
    /// the cached list is returned if there is one, so a blocked or offline
    /// network leaves the user with the servers they had rather than nothing.
    @discardableResult
    public func refresh() async throws -> [Server] {
        var lastStatus: Int?

        for source in sources {
            var request = URLRequest(url: source)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.timeoutInterval = 30

            guard let (data, response) = try? await session.data(for: request) else { continue }
            let status = (response as? HTTPURLResponse)?.statusCode
            lastStatus = status
            guard status == 200 else { continue }
            // A captive portal or a filter's block page is a 200 full of HTML.
            // Parsing is the check that matters: it either yields relays or it
            // does not.
            guard let text = String(data: data, encoding: .utf8) else { continue }
            let servers = VPNGate.servers(fromCSV: text)
            guard !servers.isEmpty else { continue }

            saveCache(servers)
            return servers
        }

        if let cached = cachedServers(), !cached.isEmpty { return cached }
        throw FetchError.allSourcesFailed(lastStatus: lastStatus)
    }

    // MARK: - Cache

    public struct Cache: Codable, Sendable {
        public var fetchedAt: Date
        public var servers: [Server]
    }

    public static func defaultCacheURL() -> URL? {
        guard let dir = try? FileManager.default.url(for: .applicationSupportDirectory,
                                                     in: .userDomainMask,
                                                     appropriateFor: nil, create: true)
        else { return nil }
        let folder = dir.appendingPathComponent("SweepVPN", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("vpngate-cache.json")
    }

    /// The cached list, whatever its age. VPN Gate relays churn within hours,
    /// so a stale entry is often dead — but a dead row that the user can see
    /// and probe beats an empty list, and the probe is what decides.
    public func cachedServers() -> [Server]? { cache()?.servers }

    public func cache() -> Cache? {
        guard let cacheURL, let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? JSONDecoder().decode(Cache.self, from: data)
    }

    private func saveCache(_ servers: [Server]) {
        guard let cacheURL else { return }
        let payload = Cache(fetchedAt: Date(), servers: servers)
        guard let data = try? JSONEncoder().encode(payload) else { return }
        try? data.write(to: cacheURL, options: .atomic)
    }

    public func clearCache() {
        guard let cacheURL else { return }
        try? FileManager.default.removeItem(at: cacheURL)
    }
}
