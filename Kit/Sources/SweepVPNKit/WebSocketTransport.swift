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

    public init(workerURL: URL = WebSocketTransport.defaultWorkerURL,
                token: String, host: String, port: UInt16) {
        self.workerURL = workerURL
        self.token = token
        self.host = host
        self.port = port
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
            if case .failed(let error) = state {
                Diagnostics.shared.record("wssListenerFailed", "\(error)")
                ready.signal()
            }
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)

        guard let bound = listener.port?.rawValue else { throw StartError.noPort }
        return bound
    }

    public func stop() {
        listener?.cancel()
        listener = nil
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

    /// The socket that carries the relay stream to the Worker.
    ///
    /// This was a `URLSession` WebSocket task and could not be. Inside a packet
    /// tunnel provider, `URLSession` evaluates its path against the network the
    /// provider itself has just taken over, and when that path is ours it opens
    /// no socket and reports no error — measured: across a full connect the
    /// extension held loopback descriptors and nothing else, no TCP to the
    /// Worker and no DNS. The connection simply never happened, silently, which
    /// is the worst possible failure mode in a transport.
    ///
    /// `NWConnection` fixes both halves. `prohibitedInterfaceTypes` keeps the
    /// socket off the tunnel by construction rather than by hoping a route
    /// exclusion covers the right addresses, and its state machine reports
    /// `.failed` and `.waiting`, so a transport that cannot connect says so.
    private func workerConnection() -> NWConnection? {
        guard let url = tunnelURL(), let name = url.host else { return nil }

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, name)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())

        // `.other` is the utun family. Our own transport must never ride the
        // tunnel it is bringing up — that is a deadlock, and once the tunnel is
        // established it would also be a loop.
        params.prohibitedInterfaceTypes = [.other]

        let websocket = NWProtocolWebSocket.Options()
        websocket.autoReplyPing = true
        params.defaultProtocolStack.applicationProtocols.insert(websocket, at: 0)

        return NWConnection(to: .url(url), using: params)
    }

    private func bridge(_ connection: NWConnection) {
        // Proves the core actually dialled loopback. Its absence next to a
        // `relayTunnelUp` means the bytes never left OpenVPN towards us, which
        // is a different bug from anything on the Worker leg.
        Diagnostics.shared.record("wssDialled")
        guard let worker = workerConnection() else { connection.cancel(); return }

        worker.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                // The Worker's first frame is a one-byte status: 0x01 connected.
                // Nothing may be forwarded before it, or the relay sees our
                // handshake interleaved with a connection that does not exist.
                self.awaitStatus(worker, connection)
            case .failed(let error):
                // "Could not reach the Worker" and "the Worker refused the
                // token" are the same symptom and completely different fixes,
                // so the reason is recorded rather than inferred later.
                Diagnostics.shared.record("wssFailed", "\(error)")
                self.tearDown(worker, connection)
            case .waiting(let error):
                // Not fatal on its own, but on this network it is how a blocked
                // path presents, and it is the state URLSession never surfaced.
                Diagnostics.shared.record("wssWaiting", "\(error)")
            default:
                break
            }
        }
        connection.start(queue: queue)
        worker.start(queue: queue)
    }

    private func tearDown(_ worker: NWConnection, _ connection: NWConnection) {
        worker.cancel()
        connection.cancel()
    }

    private func awaitStatus(_ worker: NWConnection, _ connection: NWConnection) {
        worker.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            guard error == nil, let data, data.first == 0x01 else {
                Diagnostics.shared.record(
                    "wssRefused",
                    error.map { "\($0)" } ?? "unexpected first frame")
                self.tearDown(worker, connection)
                return
            }
            Diagnostics.shared.record("wssUp")
            self.pumpSocketToWorker(connection, worker)
            self.pumpWorkerToSocket(worker, connection)
        }
    }

    /// Relay -> app.
    private func pumpWorkerToSocket(_ worker: NWConnection, _ connection: NWConnection) {
        worker.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                Diagnostics.shared.record("wssEnded", "\(error)")
                self.tearDown(worker, connection)
                return
            }
            if let data, !data.isEmpty {
                connection.send(content: data, completion: .contentProcessed { _ in })
            }
            if isComplete && data == nil {
                self.tearDown(worker, connection)
                return
            }
            self.pumpWorkerToSocket(worker, connection)
        }
    }

    /// App -> relay.
    private func pumpSocketToWorker(_ connection: NWConnection, _ worker: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let metadata = NWProtocolWebSocket.Metadata(opcode: .binary)
                let context = NWConnection.ContentContext(identifier: "relay",
                                                          metadata: [metadata])
                worker.send(content: data, contentContext: context,
                            completion: .contentProcessed { _ in })
            }
            if isComplete || error != nil {
                self.tearDown(worker, connection)
                return
            }
            self.pumpSocketToWorker(connection, worker)
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
    ///
    /// This is the only form anything inside the extension may use. The live
    /// lookup is named for what it does precisely so that reaching for it there
    /// reads as a mistake: a resolution attempted from inside the tunnel, with
    /// the blackhole already installed, comes back empty.
    public func workerAddresses(appGroup: String, timeout: TimeInterval = 3) -> Set<String> {
        let cached = Self.cachedAddresses(appGroup: appGroup)
        if !cached.isEmpty { return cached }
        return liveWorkerAddresses(timeout: timeout)
    }

    public func liveWorkerAddresses(timeout: TimeInterval = 3) -> Set<String> {
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
