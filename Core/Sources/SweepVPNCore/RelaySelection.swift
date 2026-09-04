import Foundation

/// The public relay the user picked, shared between the app and the extension.
///
/// It does not travel as an IPC message alone, and it is not in the signed
/// bundle, for two different reasons:
///
/// - The extension process is torn down and restarted by on-demand. A choice
///   that lived only in the running provider would be forgotten on the first
///   restart, and the tunnel would come back up somewhere else — or nowhere.
/// - A relay cannot go in the signed bundle at all. That bundle is vouched for
///   by the user's offline key; a VPN Gate row is a stranger's row fetched over
///   the network, and signing it with that key would make the signature mean
///   nothing.
///
/// So it lives here: unsigned, clearly separate, and only ever usable on the
/// OpenVPN rungs that `ProtocolPreference.automatic` refuses to select. The
/// worst a tampered entry can do is offer a relay the user still had to choose.
public struct RelaySelectionStore: Sendable {
    private let suiteName: String?
    private let key = "sweep.selectedRelay"
    private let poolKey = "sweep.selectedRelayPool"

    public init(appGroup: String) { self.suiteName = appGroup }

    /// Test seam.
    public init(suiteName: String?) { self.suiteName = suiteName }

    private var defaults: UserDefaults? {
        suiteName.flatMap { UserDefaults(suiteName: $0) }
    }

    /// The whole pool, best first.
    ///
    /// A pool rather than a pin because a VPN Gate relay is a volunteer's
    /// machine that drops sessions without warning — measured: an idle TCP
    /// session FIN'd at 62 s, a live one at 92 s, and a re-auth to the same
    /// relay immediately after came back AUTH_FAILED. With one relay stored,
    /// every one of those ends the tunnel for good, because there is nothing
    /// for the coordinator to move to. With alternates here it is a handover.
    public func loadAll() -> [Server] {
        guard let defaults else { return [] }
        if let data = defaults.data(forKey: poolKey),
           let pool = try? JSONDecoder().decode([Server].self, from: data) {
            let relays = pool.filter(\.isThirdPartyRelay)
            if !relays.isEmpty { return relays }
        }
        return load().map { [$0] } ?? []
    }

    public func saveAll(_ servers: [Server]) {
        guard let defaults else { return }
        let relays = servers.filter(\.isThirdPartyRelay)
        guard let head = relays.first, let data = try? JSONEncoder().encode(relays) else { return }
        defaults.set(data, forKey: poolKey)
        save(head)   // keeps `load()` meaningful for anything still reading the pin
    }

    public func load() -> Server? {
        guard let defaults, let data = defaults.data(forKey: key) else { return nil }
        guard let server = try? JSONDecoder().decode(Server.self, from: data) else { return nil }
        // Only ever hand back something that is actually a relay. If this ever
        // decodes to one of our own WireGuard servers, the store has been
        // written by something that should not have, and the signed path — not
        // this one — is where such a server belongs.
        guard server.isThirdPartyRelay else { return nil }
        return server
    }

    public func save(_ server: Server) {
        guard let defaults, server.isThirdPartyRelay,
              let data = try? JSONEncoder().encode(server) else { return }
        defaults.set(data, forKey: key)
    }

    public func clear() {
        defaults?.removeObject(forKey: key)
        defaults?.removeObject(forKey: poolKey)
    }
}

/// How long each relay has actually held a tunnel, so the pool can be ordered
/// by the thing that matters rather than only by how fast it answers a ping.
///
/// `Server.reliability` has been in the score since the beginning
/// (`ServerScoring.score`, weight 0.6) and described as an "on-device rolling
/// measure", but nothing ever wrote it — every relay sat at the default 1 and
/// the term did nothing. This is what writes it. A VPN Gate relay is a
/// volunteer's machine: two relays with identical RTT are not remotely
/// equivalent if one holds five minutes and the other drops at ten seconds, and
/// RTT cannot tell them apart.
public struct RelayStabilityStore: Sendable {
    private let suiteName: String?
    private let key = "sweep.relayStability"

    public init(appGroup: String) { self.suiteName = appGroup }
    public init(suiteName: String?) { self.suiteName = suiteName }

    private var defaults: UserDefaults? { suiteName.flatMap { UserDefaults(suiteName: $0) } }

    /// A relay that holds this long is as good as the measure can say. Chosen
    /// against the measured lifetimes: the volunteer relays that were dying in
    /// one to ten minutes should spread across the range, not all pin at 1.
    public static let idealSeconds: Double = 300

    /// Weight on the newest sample. High, because a relay's behaviour today
    /// says much more than what it did an hour ago.
    private static let alpha = 0.4

    public func loadAll() -> [String: Double] {
        (defaults?.dictionary(forKey: key) as? [String: Double]) ?? [:]
    }

    /// Fold one observed session length into the relay's rolling average.
    public func record(_ id: String, lasted seconds: Double) {
        guard let defaults, seconds.isFinite, seconds >= 0 else { return }
        var all = loadAll()
        let previous = all[id]
        all[id] = previous.map { $0 + Self.alpha * (seconds - $0) } ?? seconds
        // Unbounded growth here would be a slow leak in a shared suite; the pool
        // is sixteen and the list churns, so keep it near that order.
        if all.count > 64, let oldestWeakest = all.min(by: { $0.value < $1.value })?.key {
            all.removeValue(forKey: oldestWeakest)
        }
        defaults.set(all, forKey: key)
    }

    /// 0…1 for the score. Unmeasured relays stay at 1 — optimism is right for a
    /// relay nobody has tried, and the first session it drops corrects it.
    public func reliability(for id: String) -> Double {
        guard let seconds = loadAll()[id] else { return 1 }
        return min(1, max(0, seconds / Self.idealSeconds))
    }

    /// The pool with `reliability` filled in, ready for `ServerCatalog`.
    public func applied(to servers: [Server]) -> [Server] {
        let all = loadAll()
        guard !all.isEmpty else { return servers }
        return servers.map { server in
            guard let seconds = all[server.id] else { return server }
            var copy = server
            copy.reliability = min(1, max(0, seconds / Self.idealSeconds))
            return copy
        }
    }
}
