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

    public init(appGroup: String) { self.suiteName = appGroup }

    /// Test seam.
    public init(suiteName: String?) { self.suiteName = suiteName }

    private var defaults: UserDefaults? {
        suiteName.flatMap { UserDefaults(suiteName: $0) }
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
    }
}
