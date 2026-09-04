#if os(macOS)
import Foundation
import Network
import os
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

    /// Called when the Worker's verdict on this relay is "unusable": it
    /// declined the host, refused the token, or never answered at all.
    ///
    /// Without this the verdict was only logged. OpenVPN 3 saw nothing but a
    /// loopback socket that went quiet, so it redialled the same dead relay on
    /// its own ten-second timer — measured in the field as a 26-second handover
    /// where the coordinator had already picked a replacement in 3 ms. The
    /// relay is what failed, and only the coordinator can move off it.
    public var onUnusable: (@Sendable () -> Void)?

    private let workerURL: URL
    private let token: String
    private let host: String
    private let port: UInt16
    private let appGroup: String
    private let queue = DispatchQueue(label: "vpn.sweep.wstransport")
    private var listener: NWListener?

    public init(workerURL: URL = WebSocketTransport.defaultWorkerURL,
                token: String, host: String, port: UInt16,
                appGroup: String = AppGroupID.resolved) {
        self.appGroup = appGroup
        self.workerURL = workerURL
        self.token = token
        self.host = host
        self.port = port
    }

    /// Starts the loopback listener and returns the port it bound.
    public func start() throws -> UInt16 {
        let tcp = NWProtocolTCP.Options()
        // Nagle has no business on a tunnel transport. Every write here is
        // already a whole OpenVPN record that the far end is waiting on, so
        // holding a small one back for up to 40 ms just to coalesce it adds
        // that delay to every request the user makes — and, stacked on the
        // outer TCP to the Worker, it is what makes a page load feel like the
        // link is dead rather than slow.
        tcp.noDelay = true
        let params = NWParameters(tls: nil, tcp: tcp)
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

    /// The request target. Only the path and query travel in the request line;
    /// the host travels in `Host` and in SNI, because the socket is opened to
    /// an address.
    private func tunnelPath() -> String {
        var components = URLComponents()
        components.path = "/tcp"
        components.queryItems = [
            URLQueryItem(name: "h", value: host),
            URLQueryItem(name: "p", value: String(port)),
            URLQueryItem(name: "t", value: token),
        ]
        return components.string ?? "/tcp"
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
        guard let name = workerURL.host else { return nil }
        // The address the app resolved while it was still outside the tunnel.
        // Rotating through them means one Cloudflare address being unreachable
        // is a retry rather than a dead tunnel.
        let addresses = RelayTunnelSettings.cachedWorkerAddresses(appGroup: appGroup)
        guard let address = addresses.randomElement(),
              let ipv4 = IPv4Address(address) else {
            Diagnostics.shared.record("wssNoAddress",
                                      "the app has not resolved the Worker yet")
            return nil
        }

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, name)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true   // same reason as the loopback listener
        let params = NWParameters(tls: tls, tcp: tcp)

        // `.other` is the utun family. Our own transport must never ride the
        // tunnel it is bringing up — that is a deadlock, and once the tunnel is
        // established it would also be a loop.
        params.prohibitedInterfaceTypes = [.other]
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
        }

        // No `NWProtocolWebSocket`: see `MinimalWebSocket` for the measurements.
        return NWConnection(to: .hostPort(host: .ipv4(ipv4), port: NWEndpoint.Port(rawValue: 443)!),
                            using: params)
    }

    private func bridge(_ connection: NWConnection) {
        // Proves the core actually dialled loopback. Its absence next to a
        // `relayTunnelUp` means the bytes never left OpenVPN towards us, which
        // is a different bug from anything on the Worker leg.
        Diagnostics.shared.record("wssDialled")
        guard let worker = workerConnection(), let name = workerURL.host else {
            // No resolved Worker address means this relay cannot be dialled at
            // all. Cancelling in silence left OpenVPN 3 staring at a loopback
            // socket that closed for no stated reason; the coordinator has to
            // hear about it like any other unusable relay.
            connection.cancel()
            onUnusable?()
            return
        }
        let socket = MinimalWebSocket(connection: worker, host: name, path: tunnelPath())

        worker.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                socket.handshake { error in
                    if let error {
                        // "Could not reach the Worker" and "the Worker refused
                        // the token" are the same symptom and completely
                        // different fixes, so the reason is recorded rather
                        // than inferred later.
                        Diagnostics.shared.record("wssHandshakeFailed", "\(error)")
                        self.giveUp(worker, connection)
                        return
                    }
                    Diagnostics.shared.record("wssUpgraded")
                    self.awaitStatus(socket, worker, connection)
                }
            case .failed(let error):
                Diagnostics.shared.record("wssFailed", "\(error)")
                self.giveUp(worker, connection)
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

        // A transport that cannot connect must say so. `NWConnection` reports
        // `.failed` for a refusal and `.waiting` for an unusable path, but a
        // SYN into a blackhole produces neither — it stays `.preparing`
        // forever, which is how this bug hid for days behind a log that simply
        // stopped. Whatever the next cause turns out to be, it leaves a line.
        queue.asyncAfter(deadline: .now() + Self.readyDeadline) { [weak self] in
            guard let self, worker.state != .ready, worker.state != .cancelled else { return }
            Diagnostics.shared.record(
                "wssStalled",
                "no response from the Worker in \(Int(Self.readyDeadline))s (state: \(worker.state))")
            self.tearDown(worker, connection)
        }
    }

    /// Shorter than OpenVPN's own ten-second retry, so the stall is recorded
    /// against the attempt that caused it rather than the one after.
    private static let readyDeadline: TimeInterval = 8

    /// Comfortably inside OpenVPN 3's ten-second retry, so a relay the Worker
    /// cannot reach is handed over before the core starts redialling it.
    private static let statusDeadline: TimeInterval = 6

    private func tearDown(_ worker: NWConnection, _ connection: NWConnection) {
        worker.cancel()
        connection.cancel()
    }

    /// Tear down *and* say the relay is unusable, so the coordinator burns it
    /// and hands over instead of leaving OpenVPN 3 to retry it.
    private func giveUp(_ worker: NWConnection, _ connection: NWConnection) {
        tearDown(worker, connection)
        onUnusable?()
    }

    /// The Worker's first frame is a one-byte status: 0x01 connected. Nothing
    /// may be forwarded before it, or the relay sees our handshake interleaved
    /// with a connection that does not exist.
    private func awaitStatus(_ socket: MinimalWebSocket, _ worker: NWConnection,
                             _ connection: NWConnection) {
        let seenStatus = OSAllocatedUnfairLock(initialState: false)
        let openedAt = Date()

        // An upgraded socket that never carries a status byte is a relay the
        // Worker is still failing to reach. Nothing bounded this before, so the
        // stall ran until OpenVPN 3's own retry — the Worker's `0x00` for a
        // declined relay arrived a full 9 s after the upgrade in the field log.
        let statusDeadline = DispatchWorkItem { [weak self] in
            guard let self, !seenStatus.withLock({ $0 }) else { return }
            Diagnostics.shared.record(
                "wssStatusTimedOut",
                "the Worker upgraded but never reached this relay in \(Int(Self.statusDeadline))s")
            self.giveUp(worker, connection)
        }
        queue.asyncAfter(deadline: .now() + Self.statusDeadline, execute: statusDeadline)
        socket.receive(onMessage: { [weak self] data in
            guard let self else { return }
            let first = seenStatus.withLock { seen -> Bool in
                defer { seen = true }
                return !seen
            }
            if first {
                guard data.first == 0x01 else {
                    Diagnostics.shared.record("wssRefused", "the Worker declined this relay")
                    self.giveUp(worker, connection)
                    return
                }
                Diagnostics.shared.record("wssUp")
                self.pumpSocketToWorker(connection, socket, worker)
                return
            }
            connection.send(content: data, completion: .contentProcessed { _ in })
        }, onClose: { [weak self] error in
            // A clean close here is almost never the Worker: the Worker closes
            // 1000 "eof" when the *relay* drops its TCP session, which is what
            // a VPN Gate volunteer relay does on its own schedule (measured: an
            // idle session FIN'd at 62 s, a live one at 92 s). Saying "the
            // Worker closed" sent the last investigation at Cloudflare for a
            // day. Name the relay, since that is what actually went away.
            Diagnostics.shared.record(
                "wssEnded",
                error.map { "\($0)" }
                    ?? "relay \(self?.host ?? "?") dropped the session "
                        + "(\(socket.closeSummary ?? "stream ended, no close frame")) "
                        + "after \(Int(Date().timeIntervalSince(openedAt)))s")
            self?.tearDown(worker, connection)
        })
    }

    /// App -> relay.
    private func pumpSocketToWorker(_ connection: NWConnection, _ socket: MinimalWebSocket,
                                    _ worker: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { socket.send(data) }
            if isComplete || error != nil {
                self.tearDown(worker, connection)
                return
            }
            self.pumpSocketToWorker(connection, socket, worker)
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
    /// The Worker's own addresses, without the system resolvers that share
    /// `addressesKey`. The exclusion list wants both; something dialling the
    /// Worker must have only these, or it will try to open a tunnel to 8.8.8.8.
    private static let workerAddressesKey = "sweep.relayTunnel.workerAddresses"

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

    /// The Worker's addresses alone, for dialling.
    public static func cache(workerAddresses: Set<String>, appGroup: String) {
        guard !workerAddresses.isEmpty else { return }
        UserDefaults(suiteName: appGroup)?
            .set(Array(workerAddresses).sorted(), forKey: workerAddressesKey)
    }

    /// IPv4 addresses of the Worker, newest resolution first-equal. Empty when
    /// the app has never run — the transport says so rather than falling back
    /// to a name it cannot resolve from inside the tunnel.
    public static func cachedWorkerAddresses(appGroup: String) -> [String] {
        (UserDefaults(suiteName: appGroup)?.stringArray(forKey: workerAddressesKey) ?? [])
            .filter { !$0.contains(":") }
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
