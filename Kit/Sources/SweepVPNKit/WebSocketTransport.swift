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
    /// Every leg this transport has bridged and not yet torn down.
    /// `stop()` used to cancel only the listener, so a leg outlived the
    /// transport that owned it: its socket still received the Worker's
    /// `1000 "eof"`, but by then `self` was gone and the handler bailed at its
    /// `guard let self`. The relay-gone verdict was dropped on the floor and
    /// the coordinator — the only thing that can move to another relay — never
    /// heard about it, which is the 20-35 s of dead tunnel in the field log
    /// (`relay ? dropped the session`, where the `?` is the missing `self`).
    /// Owning the legs is what makes `stop()` mean stop. Only `queue` touches
    /// this, like every other leg field.
    private var legs: [Leg] = []

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
        // Cancelling the listener only stops *new* legs. The ones already
        // bridged have to be torn down here, or they outlive this object and
        // report their verdicts into a deallocated `self`.
        queue.async { [self] in
            for leg in legs { tearDown(leg, nil) }
            legs.removeAll()
        }
    }

    // MARK: - One connection

    /// The request target. Only the path and query travel in the request line;
    /// the host travels in `Host` and in SNI, because the socket is opened to
    /// an address.
    func tunnelPath(session: String, resuming: Bool = false) -> String {
        var components = URLComponents()
        components.path = "/tcp"
        components.queryItems = [
            URLQueryItem(name: "h", value: host),
            URLQueryItem(name: "p", value: String(port)),
            URLQueryItem(name: "t", value: token),
            // Names the session on the Worker side. Redialling with the same id
            // re-attaches to the relay socket that is still open there, instead
            // of opening a new one and making OpenVPN start over.
            URLQueryItem(name: "s", value: session),
        ]
        // Says this is a redial, so the Worker refuses to answer it with a
        // fresh relay socket the OpenVPN session could not have resumed.
        if resuming { components.queryItems?.append(URLQueryItem(name: "r", value: "1")) }
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
        // The URL's port when it carries one, 443 otherwise. Hardcoding 443
        // meant a `workerURL` naming any other port was silently dialled on the
        // wrong one — which in production is always 443, but made the leg
        // untestable against a stand-in.
        let port = workerURL.port.flatMap { UInt16(exactly: $0) } ?? 443
        return NWConnection(to: .hostPort(host: .ipv4(ipv4),
                                          port: NWEndpoint.Port(rawValue: port)!),
                            using: params)
    }

    /// One OpenVPN connection through the Worker.
    ///
    /// It exists because the leg to the Worker is no longer the same lifetime as
    /// the OpenVPN session riding on it. When the Worker leg drops, this holds
    /// the loopback socket open, redials the *same* Worker session, and hands
    /// the stream back — OpenVPN never learns anything happened.
    ///
    /// `@unchecked` because every field is touched only from `queue`: the
    /// listener, both connections' state handlers, the socket's callbacks and
    /// every `asyncAfter` in here all run there, and it is serial.
    private final class Leg: @unchecked Sendable {
        let connection: NWConnection
        /// Stable for the life of the OpenVPN session; it is what the Worker
        /// matches a redial against.
        let session = UUID().uuidString
        var socket: MinimalWebSocket?
        /// The leg owns its Worker connection so `tearDown` can cancel it.
        /// `stop()` has no worker to hand in, so without this the socket to
        /// Cloudflare outlived the transport and reported its close into a
        /// deallocated `self` — the `wssVerdictOrphaned` in the logs.
        var worker: NWConnection?
        /// Which dial attempt is current. Every callback carries the generation
        /// it was armed by, so the ones belonging to an attempt we have already
        /// moved on from cannot fire a second failure for the same event —
        /// which is exactly what a dropped leg used to do: the socket's error
        /// callback asked for a redial and `NWConnection`'s `.failed` burned the
        /// relay a moment later, so the redial never ran and every blip cost a
        /// relay.
        var generation = 0
        var attempts = 0
        var pumping = false
        var closed = false
        /// App -> relay bytes that arrived mid-redial. Small by construction:
        /// the redial budget is about a second and OpenVPN is not chatty while
        /// it is waiting on a reply.
        var outbound: [Data] = []

        init(_ connection: NWConnection) { self.connection = connection }
    }

    /// How many times a dropped Worker leg is redialled before the relay itself
    /// is declared unusable. Four attempts at 150 ms is well inside OpenVPN 3's
    /// own ten-second retry, so a redial that works is invisible and one that
    /// does not still reaches the coordinator long before the core gives up.
    static let redialBudget = 4
    static let redialBackoff: TimeInterval = 0.15

    /// What a leg ending means for the relay behind it.
    enum Disposition: Equatable {
        /// Our leg to the Worker died. The relay's session is still parked in
        /// the Durable Object, so redialling resumes it and OpenVPN sees nothing.
        case ourLeg
        /// The Worker is telling us about the relay: it hung up (1000 "eof") or
        /// the Worker will not carry it (1008). Redialling cannot change that.
        case relayGone
    }

    /// A close frame carries the Worker's verdict; its absence — including the
    /// synthetic 1006 an abnormal end is reported as, and a bare transport
    /// error — means our own leg dropped.
    static func disposition(closeCode: Int?) -> Disposition {
        guard let closeCode, closeCode != 1006 else { return .ourLeg }
        return .relayGone
    }

    private func bridge(_ connection: NWConnection) {
        // Proves the core actually dialled loopback. Its absence next to a
        // `relayTunnelUp` means the bytes never left OpenVPN towards us, which
        // is a different bug from anything on the Worker leg.
        Diagnostics.shared.record("wssDialled")
        let leg = Leg(connection)
        legs.append(leg)
        connection.start(queue: queue)
        dial(leg)
    }

    private func dial(_ leg: Leg) {
        guard !leg.closed else { return }
        leg.generation += 1
        let generation = leg.generation
        guard let worker = workerConnection(), let name = workerURL.host else {
            // No resolved Worker address means this relay cannot be dialled at
            // all. Cancelling in silence left OpenVPN 3 staring at a loopback
            // socket that closed for no stated reason; the coordinator has to
            // hear about it like any other unusable relay.
            giveUp(leg, nil)
            return
        }
        leg.worker = worker
        let socket = MinimalWebSocket(connection: worker, host: name,
                                      path: tunnelPath(session: leg.session,
                                                       resuming: leg.attempts > 0))

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
                        // An HTTP answer we did not want is the Worker's
                        // decision and will be the same next time; anything
                        // else is transport, and transport is what redialling
                        // is for.
                        if case MinimalWebSocket.WebSocketError.handshakeFailed = error {
                            self.giveUp(leg, worker)
                        } else {
                            self.legFailed(leg, worker, generation)
                        }
                        return
                    }
                    Diagnostics.shared.record("wssUpgraded")
                    self.awaitStatus(socket, worker, leg, generation)
                }
            case .failed(let error):
                // Our socket to the Worker, not the relay. `POSIXErrorCode 60`
                // here is a path that went away under a live session, and the
                // relay on the other side of the Durable Object is still there
                // — burning it, as this used to, threw away a good relay and
                // made OpenVPN renegotiate for a fault it never saw.
                Diagnostics.shared.record("wssFailed", "\(error)")
                self.legFailed(leg, worker, generation)
            case .waiting(let error):
                // Not fatal on its own, but on this network it is how a blocked
                // path presents, and it is the state URLSession never surfaced.
                Diagnostics.shared.record("wssWaiting", "\(error)")
            default:
                break
            }
        }
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
            self.legFailed(leg, worker, generation)
        }
    }

    /// Shorter than OpenVPN's own ten-second retry, so the stall is recorded
    /// against the attempt that caused it rather than the one after.
    private static let readyDeadline: TimeInterval = 8

    /// Comfortably inside OpenVPN 3's ten-second retry, so a relay the Worker
    /// cannot reach is handed over before the core starts redialling it.
    static let statusDeadline: TimeInterval = 6

    /// The Worker leg went away. Try to get it back before anyone notices.
    ///
    /// This is the whole point of the Durable Object on the other side: the
    /// relay's TCP session is still open there, so a redial with the same
    /// session id resumes it. What used to cost a full OpenVPN renegotiation —
    /// RESOLVE, WAIT, CONNECTING, GET_CONFIG, ASSIGN_IP, and about two seconds
    /// of dead internet, every few seconds in the field log — now costs a
    /// reconnect the core never sees.
    /// This attempt's leg to the Worker failed. Redial it; the relay is not at
    /// fault and must not be burned until the redials are exhausted.
    ///
    /// The generation check is what makes this idempotent: a leg drop is
    /// reported twice — once by the socket, once by `NWConnection`'s state — and
    /// acting on both meant scheduling a redial and then tearing the leg down
    /// before it could run.
    private func legFailed(_ leg: Leg, _ worker: NWConnection?, _ generation: Int) {
        guard leg.generation == generation, !leg.closed else { return }
        redial(leg, worker)
    }

    private func redial(_ leg: Leg, _ worker: NWConnection?) {
        leg.socket?.stopKeepalive()
        worker?.cancel()
        leg.socket = nil
        guard !leg.closed else { return }
        guard leg.attempts < Self.redialBudget else {
            Diagnostics.shared.record(
                "wssReattachExhausted",
                "the Worker leg would not come back in \(Self.redialBudget) tries")
            giveUp(leg, nil)
            return
        }
        leg.attempts += 1
        // Backing off geometrically keeps a four-attempt budget inside OpenVPN
        // 3's own ten-second retry (0.15 + 0.3 + 0.6 + 1.2 s) while still
        // giving a path that is merely re-routing time to come back.
        let delay = Self.redialBackoff * pow(2, Double(leg.attempts - 1))
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.dial(leg)
        }
    }

    private func tearDown(_ leg: Leg, _ worker: NWConnection?) {
        leg.closed = true
        leg.socket?.stopKeepalive()
        leg.socket = nil
        leg.outbound.removeAll()
        worker?.cancel()
        leg.worker?.cancel()
        leg.worker = nil
        leg.connection.cancel()
        legs.removeAll { $0 === leg }
    }

    /// Tear down *and* say the relay is unusable, so the coordinator burns it
    /// and hands over instead of leaving OpenVPN 3 to retry it.
    private func giveUp(_ leg: Leg, _ worker: NWConnection?) {
        // `legFailed` has always guarded on `closed`; this did not, so a close
        // frame arriving from a leg we had already given up on burned a second
        // relay — one the tunnel was not even using by then.
        guard !leg.closed else { return }
        tearDown(leg, worker)
        onUnusable?()
    }

    /// The Worker's first frame is a one-byte status: 0x01 connected. Nothing
    /// may be forwarded before it, or the relay sees our handshake interleaved
    /// with a connection that does not exist.
    private func awaitStatus(_ socket: MinimalWebSocket, _ worker: NWConnection, _ leg: Leg,
                             _ generation: Int) {
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
            self.giveUp(leg, worker)
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
                    // A refusal is about the relay, not about this leg, so it
                    // is never worth redialling: the answer would be the same.
                    Diagnostics.shared.record("wssRefused", "the Worker declined this relay")
                    self.giveUp(leg, worker)
                    return
                }
                if leg.attempts == 0 {
                    Diagnostics.shared.record("wssUp")
                } else {
                    Diagnostics.shared.record(
                        "wssReattached",
                        "the relay session survived the drop; OpenVPN never saw it")
                }
                leg.socket = socket
                // The status deadline is not cancelled here: it already
                // no-ops once `seenStatus` is set, and a `DispatchWorkItem` is
                // not `Sendable` to capture in this callback.
                // A leg that goes quiet is the failure this transport could not
                // see: nothing else here notices until the kernel gives up on
                // its retransmissions, a minute or more later, with the tunnel
                // dead throughout.
                socket.startKeepalive(on: self.queue) { [weak self] in
                    guard let self else { return }
                    Diagnostics.shared.record(
                        "wssIdle",
                        "no byte from the Worker in \(Int(MinimalWebSocket.idleDeadline))s; redialling")
                    self.legFailed(leg, worker, generation)
                }
                // Anything OpenVPN sent while the leg was down goes first, in
                // order, or the relay sees a hole in its stream.
                for pending in leg.outbound { socket.send(pending) }
                leg.outbound.removeAll()
                self.pumpSocketToWorker(leg)
                return
            }
            // Traffic, not a status byte, is what proves the leg is good. The
            // budget resets here and nowhere else: a Worker that answers 0x01
            // and then closes at once would otherwise refill the budget on
            // every attempt and redial forever — measured, about twenty times
            // in ten seconds before OpenVPN gave up and renegotiated anyway,
            // with the internet dead throughout.
            leg.attempts = 0
            leg.connection.send(content: data, completion: .contentProcessed { _ in })
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
            guard let self else {
                // Unreachable now that `stop()` tears its legs down, but a
                // silently dropped verdict is what cost the last two sessions.
                // If it ever happens again it says so in the log instead of
                // looking like the tunnel simply went quiet.
                Diagnostics.shared.record(
                    "wssVerdictOrphaned",
                    "a leg outlived its transport; the relay verdict was lost")
                return
            }
            // The Worker closes 1000 "eof" when the *relay* hung up, and 1008
            // when it will not carry this relay at all. Neither is our leg
            // failing, so neither is worth a redial — the relay is gone and
            // only the coordinator can move off it. A stream that ends with no
            // close frame is the opposite case: our leg, and redialling it is
            // the whole point.
            if Self.disposition(closeCode: socket.closeCode) == .relayGone {
                Diagnostics.shared.record(
                    "wssRelayFinished",
                    "the Worker closed \(socket.closeCode.map(String.init) ?? "?"); "
                        + "handing over rather than redialling a relay that is gone")
                self.giveUp(leg, worker)
                return
            }
            self.legFailed(leg, worker, generation)
        })
    }

    /// App -> relay. One loop for the life of the loopback connection, however
    /// many Worker legs it outlives.
    private func pumpSocketToWorker(_ leg: Leg) {
        guard !leg.pumping, !leg.closed else { return }
        leg.pumping = true
        pumpNext(leg)
    }

    private func pumpNext(_ leg: Leg) {
        leg.connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if let socket = leg.socket {
                    socket.send(data)
                } else {
                    // Mid-redial. Holding these is what makes the reconnect
                    // invisible; dropping them would corrupt the OpenVPN stream
                    // just as surely as the disconnect did.
                    leg.outbound.append(data)
                }
            }
            if isComplete || error != nil {
                // OpenVPN closed its end. Nothing left to keep alive.
                self.tearDown(leg, nil)
                return
            }
            self.pumpNext(leg)
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
