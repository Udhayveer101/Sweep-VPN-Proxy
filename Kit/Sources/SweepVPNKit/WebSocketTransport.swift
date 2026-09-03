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
                connection.cancel()
                task.cancel(with: .goingAway, reason: nil)
                return
            }
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
    public func workerAddresses() -> Set<String> {
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
