#if os(macOS)
import Foundation
import Network
import SweepVPNCore

/// Carries a relay's TCP stream inside a WebSocket to our Cloudflare Worker.
///
/// # Why the tunnel is shaped like this
///
/// The gateway on this network fingerprints plaintext protocol signatures and
/// resets an OpenVPN handshake wherever it sees one, port 443 included. It does
/// not inspect TLS, so it cannot see inside an HTTPS session to a host it has
/// not categorised. Wrapping the same OpenVPN bytes in WSS to `workers.dev`
/// therefore gets them past it untouched (measured: the transport reset
/// disappears and the tunnel completes).
///
/// # Why a loopback listener instead of a socket the adapter hands over
///
/// OpenVPN 3 opens its own socket from inside the C++ core; there is no seam to
/// pass it a pre-connected one without patching the core. So this listens on
/// 127.0.0.1, and `OpenVPNTunnelAdapter` rewrites the profile's `remote` to
/// point here. The core dials loopback and is entirely unaware — which is what
/// keeps the adapter, the framing fix and the credentials all unchanged.
public final class WebSocketTransport: @unchecked Sendable {

    public enum StartError: Error, Equatable {
        case listenerFailed(String)
        case noPort
    }

    /// The deployed Worker. Overridable so a rebuilt Worker on another account
    /// does not need a new build.
    public static let defaultWorkerURL =
        URL(string: "https://relay-worker.example.workers.dev")!

    private let workerURL: URL
    private let token: String
    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "vpn.sweep.wstransport")
    private var listener: NWListener?
    private let session: URLSession

    public init(workerURL: URL = WebSocketTransport.defaultWorkerURL,
                token: String, host: String, port: UInt16) {
        self.workerURL = workerURL
        self.token = token
        self.host = host
        self.port = port
        let config = URLSessionConfiguration.ephemeral
        // The tunnel must not be routed back into our own VPN once it comes up,
        // and it must not sit behind a system proxy the user set for browsing.
        config.connectionProxyDictionary = [:]
        self.session = URLSession(configuration: config)
    }

    /// Starts the loopback listener and returns the port it bound.
    public func start() throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        // Bind IPv4 loopback explicitly. `requiredInterfaceType = .loopback`
        // alone leaves the family to the system, and OpenVPN 3 dials the
        // rewritten `remote 127.0.0.1 <port>` from its own BSD socket — strictly
        // IPv4. A listener that came up on ::1 refused that connection
        // instantly, which surfaced as a bare NETWORK_RECV_ERROR less than a
        // second after the tunnel started and never reached the bridge at all.
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        params.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: params) else {
            throw StartError.listenerFailed("could not create a loopback listener")
        }
        self.listener = listener

        listener.newConnectionHandler = { [weak self] connection in
            self?.bridge(connection)
        }

        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
            if case .failed = state { ready.signal() }
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)

        guard let bound = listener.port?.rawValue else { throw StartError.noPort }
        return bound
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        session.invalidateAndCancel()
    }

    // MARK: - One connection

    private func tunnelURL() -> URL? {
        var components = URLComponents(url: workerURL, resolvingAgainstBaseURL: false)
        components?.scheme = workerURL.scheme == "http" ? "ws" : "wss"
        components?.path = "/tcp"
        components?.queryItems = [
            URLQueryItem(name: "h", value: host),
            URLQueryItem(name: "p", value: String(port)),
            URLQueryItem(name: "t", value: token),
        ]
        return components?.url
    }

    private func bridge(_ connection: NWConnection) {
        guard let url = tunnelURL() else { connection.cancel(); return }
        let task = session.webSocketTask(with: url)
        task.resume()
        connection.start(queue: queue)

        // The Worker's first frame is a one-byte status: 0x01 connected.
        // Nothing may be forwarded before it, or the relay sees our handshake
        // interleaved with a connection that does not exist yet.
        task.receive { [weak self] result in
            guard let self else { return }
            guard case .success(.data(let status)) = result, status.first == 0x01 else {
                // Without this the bypass failed as a bare NETWORK_RECV_ERROR
                // from OpenVPN — the loopback hung up, and nothing anywhere
                // said why. "Could not reach the Worker" and "the Worker
                // refused the token" are the same symptom and completely
                // different fixes.
                switch result {
                case .failure(let error):
                    Diagnostics.shared.record("wssFailed", "\(error)")
                case .success(let message):
                    Diagnostics.shared.record("wssRefused", "unexpected first frame \(message)")
                }
                connection.cancel()
                task.cancel(with: .goingAway, reason: nil)
                return
            }
            Diagnostics.shared.record("wssUp")
            self.pumpSocketToWebSocket(connection, task)
            self.pumpWebSocketToSocket(task, connection)
        }
    }

    /// Relay -> app.
    private func pumpWebSocketToSocket(_ task: URLSessionWebSocketTask, _ connection: NWConnection) {
        task.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                let data: Data
                switch message {
                case .data(let d): data = d
                case .string(let s): data = Data(s.utf8)
                @unknown default: data = Data()
                }
                if !data.isEmpty {
                    connection.send(content: data, completion: .contentProcessed { _ in })
                }
                self.pumpWebSocketToSocket(task, connection)
            case .failure:
                connection.cancel()
            }
        }
    }

    /// App -> relay.
    private func pumpSocketToWebSocket(_ connection: NWConnection, _ task: URLSessionWebSocketTask) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                task.send(.data(data)) { _ in }
            }
            if isComplete || error != nil {
                task.cancel(with: .goingAway, reason: nil)
                connection.cancel()
                return
            }
            self.pumpSocketToWebSocket(connection, task)
        }
    }
}

/// Where the tunnel's settings live, shared between the app and the extension.
///
/// The token only rate-limits our own Worker — it is not a credential that
/// protects user data — so the app group is the right home for it rather than
/// the keychain the tunnel secrets use.
public struct RelayTunnelSettings: Sendable {
    public var enabled: Bool
    public var workerURL: URL
    public var token: String

    private static let enabledKey = "sweep.relayTunnel.enabled"
    private static let urlKey = "sweep.relayTunnel.url"
    private static let tokenKey = "sweep.relayTunnel.token"

    public init(enabled: Bool, workerURL: URL, token: String) {
        self.enabled = enabled
        self.workerURL = workerURL
        self.token = token
    }

    /// Build-time value baked into whichever bundle is asking. Inside the
    /// extension `Bundle.main` is the extension, which is the whole point.
    private static func baked(_ key: String) -> String? {
        (Bundle.main.object(forInfoDictionaryKey: key) as? String)
            .flatMap { $0.isEmpty ? nil : $0 }
    }

    public static func load(appGroup: String) -> RelayTunnelSettings {
        let defaults = UserDefaults(suiteName: appGroup)
        // The app group is the primary source so a redeployed Worker takes
        // effect without a rebuild. It falls back to the value baked into this
        // bundle because the group is only ever populated by the app window's
        // launch task: an extension started on demand — at boot, or before the
        // window has been opened since install — would otherwise read an empty
        // token, skip the tunnel, and put OpenVPN on the wire in plaintext,
        // which is precisely what the gateway resets.
        let url = (defaults?.string(forKey: urlKey)).flatMap(URL.init(string:))
            ?? baked("SweepTunnelURL").flatMap(URL.init(string:))
            ?? WebSocketTransport.defaultWorkerURL
        // Default ON: on this network a direct relay connection cannot work, and
        // an off-by-default bypass is one the user has to discover.
        let enabled = defaults?.object(forKey: enabledKey) as? Bool ?? true
        let token = defaults?.string(forKey: tokenKey).flatMap { $0.isEmpty ? nil : $0 }
            ?? baked("SweepTunnelToken")
            ?? ""
        return RelayTunnelSettings(enabled: enabled, workerURL: url, token: token)
    }

    /// Addresses the Worker currently resolves to.
    ///
    /// The content filter compares flows by address, and when the relay tunnel
    /// is on, the extension's real outbound flow goes to the Worker rather than
    /// to the relay. Without these in the filter's allow-list the kill switch
    /// drops the one connection the tunnel needs in order to come up — a
    /// deadlock that fails closed and never recovers.
    ///
    /// Cloudflare's addresses rotate, so this is resolved at publish time rather
    /// than pinned. An empty result is not fatal: the filter simply has one
    /// fewer allowance, which is the safe direction to be wrong in.
    /// Resolves the Worker's addresses, giving up after `timeout`.
    ///
    /// `getaddrinfo` is synchronous and has no timeout of its own. This runs on
    /// the tunnel's start path, where it was seen to block for thirty seconds
    /// and then return nothing — half a minute in which the extension had not
    /// yet installed any settings and the user saw only "Connecting". A bounded
    /// wait that sometimes yields no addresses is strictly better: the addresses
    /// are a routing optimisation, and the connection is not made from them.
    private static let addressesKey = "sweep.relayTunnel.addresses"

    /// The addresses the app last resolved, if any.
    ///
    /// The extension cannot rely on resolving this name itself. On-demand keeps
    /// the previous session's blackhole installed while the next extension
    /// starts, so a default route we own is already in place before we have
    /// worked out what to exclude from it — the lookup goes into the dead
    /// interface and the exclusion list comes back empty, which guarantees the
    /// same failure on every subsequent attempt. The app has no such problem: it
    /// is an ordinary process outside the tunnel, so it resolves the name once
    /// and leaves the answer here.
    public static func cachedAddresses(appGroup: String) -> Set<String> {
        Set(UserDefaults(suiteName: appGroup)?.stringArray(forKey: addressesKey) ?? [])
    }

    public static func cache(addresses: Set<String>, appGroup: String) {
        guard !addresses.isEmpty else { return }   // never replace a good list with nothing
        UserDefaults(suiteName: appGroup)?.set(Array(addresses).sorted(), forKey: addressesKey)
    }

    /// Cached answer first, live lookup only as a fallback.
    public func workerAddresses(appGroup: String, timeout: TimeInterval = 3) -> Set<String> {
        let cached = Self.cachedAddresses(appGroup: appGroup)
        if !cached.isEmpty { return cached }
        return workerAddresses(timeout: timeout)
    }

    public func workerAddresses(timeout: TimeInterval = 3) -> Set<String> {
        let box = NSMutableArray()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            box.addObjects(from: Array(self.resolveWorkerAddresses()))
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else { return [] }
        return Set(box.compactMap { $0 as? String })
    }

    private func resolveWorkerAddresses() -> Set<String> {
        guard let host = workerURL.host else { return [] }

        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let head = result else { return [] }
        defer { freeaddrinfo(head) }

        var addresses: Set<String> = []
        var node: UnsafeMutablePointer<addrinfo>? = head
        while let current = node {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if let sa = current.pointee.ai_addr,
               getnameinfo(sa, current.pointee.ai_addrlen, &buffer, socklen_t(buffer.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                addresses.insert(String(cString: buffer))
            }
            node = current.pointee.ai_next
        }
        return addresses
    }

    public func save(appGroup: String) {
        let defaults = UserDefaults(suiteName: appGroup)
        defaults?.set(enabled, forKey: Self.enabledKey)
        defaults?.set(workerURL.absoluteString, forKey: Self.urlKey)
        defaults?.set(token, forKey: Self.tokenKey)
    }
}
#endif
