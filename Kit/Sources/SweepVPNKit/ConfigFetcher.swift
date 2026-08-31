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

    public let url: URL?
    private let store: ConfigStore
    private let session: URLSession

    public init(url: URL?, store: ConfigStore, session: URLSession = .shared) {
        self.url = url
        self.store = store
        self.session = session
    }

    /// Fetch, verify, and persist. Returns the bundle now in force — which on
    /// any failure is the last-known-good one, never nothing.
    @discardableResult
    public func refresh(now: Date = Date()) async throws -> ConfigBundle {
        guard let url else { throw FetchError.notConfigured }
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
        try? store.loadBundle(now: now)
    }
}
