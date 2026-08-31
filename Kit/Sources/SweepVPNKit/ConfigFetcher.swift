import Foundation
import SweepVPNCore

/// Pulls the signed config bundle from a static host and hands it to the
/// ConfigStore, which verifies it against the pinned key before anything else
/// in the app can see it.
///
/// There is no account API and no per-user endpoint: everybody downloads the
/// same signed blob, so the host learns nothing beyond "someone fetched it".
public struct ConfigFetcher: Sendable {
    public enum FetchError: Error, Equatable {
        case notConfigured
        case transport
        case rejected(String)
    }

    /// Name of the signed bundle a personal build can ship inside the app, so
    /// there is no static host to stand up at all.
    public static let bundledResourceName = "sweep-config.sig"

    public let url: URL?
    private let store: ConfigStore
    private let session: URLSession
    private let bundledURL: URL?

    public init(url: URL?, store: ConfigStore, session: URLSession = .shared,
                bundledURL: URL? = Bundle.main.url(forResource: ConfigFetcher.bundledResourceName,
                                                   withExtension: "json")) {
        self.url = url
        self.store = store
        self.session = session
        self.bundledURL = bundledURL
    }

    /// Fetch, verify, and persist. Returns the bundle now in force — which on
    /// any failure is the last-known-good one, never nothing.
    @discardableResult
    public func refresh(now: Date = Date()) async throws -> ConfigBundle {
        guard let url else {
            // No host configured: a bundle shipped in the app is the only other
            // source, and it goes through the identical verification path.
            if let bundled = try? acceptBundled(now: now) { return bundled }
            if let existing = try? store.loadBundle(now: now) { return existing }
            throw FetchError.notConfigured
        }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 20

        let data: Data
        do {
            let (payload, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw FetchError.transport
            }
            data = payload
        } catch {
            // Offline is not a security event: keep running on what we have.
            if let existing = try? store.loadBundle(now: now) { return existing }
            throw FetchError.transport
        }

        do {
            let signed = try IPCCodec.decode(SignedBundle.self, data)
            return try store.accept(signed, now: now)
        } catch {
            // A bad signature, a rollback or an expiry means we stay exactly
            // where we were. It never downgrades the running configuration.
            if let existing = try? store.loadBundle(now: now) { return existing }
            throw FetchError.rejected("\(error)")
        }
    }

    /// What the app should show right now, without touching the network.
    public func current(now: Date = Date()) -> ConfigBundle? {
        if let stored = try? store.loadBundle(now: now) { return stored }
        return try? acceptBundled(now: now)
    }

    /// Load the in-app signed bundle. This is *not* a trust shortcut: it is the
    /// same `store.accept`, the same pinned key, the same version and expiry
    /// checks — only the transport differs.
    private func acceptBundled(now: Date) throws -> ConfigBundle {
        guard let bundledURL else { throw FetchError.notConfigured }
        let signed = try IPCCodec.decode(SignedBundle.self, try Data(contentsOf: bundledURL))
        return try store.accept(signed, now: now)
    }
}
