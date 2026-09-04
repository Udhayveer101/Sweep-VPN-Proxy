#if os(macOS)
import Foundation
import os
import SweepVPNCore
import SweepOpenVPNC

/// The OpenVPN rungs, driven by OpenVPN 3 through the `sweepovpn` C shim.
///
/// This adapter is deliberately unlike `WireGuardAdapter` in two ways, and both
/// are properties of the protocol rather than of the code:
///
/// 1. **The peer is not ours.** A WireGuard rung talks to a peer whose public
///    key came out of a signed bundle, so authentication means "this is the
///    machine we meant". Here it means only "the relay presented a certificate
///    chaining to the CA in its own profile" — which every VPN Gate user shares.
///    It proves the relay is the one the list named. It proves nothing about
///    who runs it.
///
/// 2. **The address arrives late.** WireGuard knows the tunnel address before
///    it starts; OpenVPN is told in PUSH_REPLY. So `onAuthenticated` cannot fire
///    until the push has been seen and validated, and the provider has to build
///    its network settings from `pushedSettings` rather than from the `Server`
///    record, which for a relay is empty.
public final class OpenVPNTunnelAdapter: TunnelAdapter, @unchecked Sendable {
    private static let log = Logger(subsystem: "com.sweep.vpn", category: "openvpn")

    public let rung: ProtocolRung

    private let server: Server
    private let profile: String
    private let queue = DispatchQueue(label: "vpn.sweep.ovpn", qos: .userInitiated)
    /// Held for the adapter's lifetime when the relay is reached through the
    /// Worker: it owns the loopback listener the OpenVPN core dials.
    private var transport: WebSocketTransport?
    private let appGroup: String
    private let endpointHost: String
    private let endpointPort: UInt16

    /// Guarded by `lock`. It is written when the tunnel starts and read from
    /// whichever queue is sending packets or sampling stats, so it cannot be a
    /// bare stored property.
    private var _handle: OpaquePointer?
    private var handle: OpaquePointer? {
        get { lock.lock(); defer { lock.unlock() }; return _handle }
        set { lock.lock(); _handle = newValue; lock.unlock() }
    }

    private var onAuthenticated: (@Sendable () -> Void)?
    private var onInbound: (@Sendable ([Data], [NSNumber]) -> Void)?
    private var onFailure: (@Sendable (TunnelErrorKind) -> Void)?

    private let lock = NSLock()
    private var _pushed: PushedTunnelSettings?
    private var connectedAt: Date?
    private var finished = false
    /// Previous liveness sample: the inbound byte count and when it was taken.
    /// Liveness here is "did anything arrive since last time", because OpenVPN
    /// has no periodic handshake to age out.
    private var lastRxSample: (bytes: UInt64, at: Date)?

    /// What the relay assigned. Nil until the tunnel is up.
    public var pushedSettings: PushedTunnelSettings? {
        lock.lock(); defer { lock.unlock() }
        return _pushed
    }

    public init?(rung: ProtocolRung, server: Server, endpoint: ServerEndpoint,
                 appGroup: String = AppGroupID.resolved) {
        guard let profile = endpoint.openVPNProfile, !profile.isEmpty else { return nil }
        self.rung = rung
        self.server = server
        self.profile = profile
        self.appGroup = appGroup
        self.endpointHost = endpoint.host
        self.endpointPort = endpoint.port
    }

    /// Rewrite the profile so the OpenVPN core dials our loopback listener
    /// instead of the relay, and return it. On any failure the original profile
    /// is returned: a direct attempt that the gateway resets is a better outcome
    /// than refusing to try at all.
    ///
    /// Only the TCP rung is tunneled. The Worker's `connect()` is a TCP socket,
    /// so there is nothing to carry a UDP relay over.
    private func profileThroughWorker() -> String {
        let settings = RelayTunnelSettings.load(appGroup: appGroup)
        guard settings.enabled, !settings.token.isEmpty, rung == .openVPNTCP else {
            // Falling back to a direct profile on a network that resets plain
            // OpenVPN produces a 45-second handshake timeout and no reason at
            // all, so every skip says which condition sent us here.
            Self.log.error("""
                relay tunnel skipped: enabled=\(settings.enabled, privacy: .public) \
                hasToken=\(!settings.token.isEmpty, privacy: .public) \
                rung=\(self.rung.shortName, privacy: .public) — connecting directly
                """)
            Diagnostics.shared.record(
                "relayTunnelSkipped",
                "enabled=\(settings.enabled) hasToken=\(!settings.token.isEmpty) "
                    + "rung=\(rung.shortName) — DIRECT")
            return profile
        }

        let transport = WebSocketTransport(workerURL: settings.workerURL, token: settings.token,
                                           host: endpointHost, port: endpointPort)
        let localPort: UInt16
        do {
            localPort = try transport.start()
        } catch {
            Self.log.error("""
                relay tunnel failed to start: \(error, privacy: .public) — connecting directly
                """)
            Diagnostics.shared.record("relayTunnelFailed", "\(error) — DIRECT")
            return profile
        }
        Self.log.notice("relay tunnel listening on 127.0.0.1:\(localPort, privacy: .public)")
        Diagnostics.shared.record("relayTunnelUp", "loopback:\(localPort)")
        self.transport = transport

        guard let rewritten = Self.pointingAtLoopback(profile, port: localPort) else {
            Self.log.error("profile carried no `remote` line — connecting directly")
            Diagnostics.shared.record("relayTunnelUnrewritten", "no remote line — DIRECT")
            return profile
        }
        Diagnostics.shared.record("relayTunnelRewritten", "remote 127.0.0.1:\(localPort)")
        return rewritten
    }

    /// Replace every `remote` line with one pointing at our loopback listener,
    /// or nil if the profile has none. Profiles often list several relays;
    /// leaving any of them pointing outward would let OpenVPN fail over to a
    /// direct connection the gateway kills.
    static func pointingAtLoopback(_ profile: String, port: UInt16) -> String? {
        var rewritten: [String] = []
        var inserted = false
        // Split on `isNewline`, not on "\n". VPN Gate ships CRLF profiles, and
        // in Swift "\r\n" is one Character — so splitting on "\n" returned the
        // whole file as a single line, no `remote` was ever matched, and every
        // connect went out in plaintext to be reset by the gateway.
        for raw in profile.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            if raw.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("remote ") {
                if !inserted {
                    rewritten.append("remote 127.0.0.1 \(port)")
                    inserted = true
                }
                continue
            }
            rewritten.append(String(raw))
        }
        return inserted ? rewritten.joined(separator: "\n") : nil
    }

    deinit {
        if let _handle { sweep_ovpn_free(_handle) }
    }

    // MARK: - TunnelAdapter

    public func start(onAuthenticated: @escaping @Sendable () -> Void,
                      onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                      onFailure: @escaping @Sendable (TunnelErrorKind) -> Void) {
        self.onAuthenticated = onAuthenticated
        self.onInbound = onInbound
        self.onFailure = onFailure
        // Bringing up the loopback listener waits for it to become ready, and
        // the caller is the coordinator's serial queue — the same queue its
        // timers and failure handling run on. Blocking it there stalls every
        // other rung and delays the very deadlines meant to bound this attempt.
        queue.async { [weak self] in self?.startOnQueue() }
    }

    private func startOnQueue() {
        let ctx = Unmanaged.passUnretained(self).toOpaque()

        let created = profileThroughWorker().withCString { cProfile in
            sweep_ovpn_new(cProfile,
                           { ctx, data, len, family in
                               guard let ctx, let data else { return }
                               let me = Unmanaged<OpenVPNTunnelAdapter>
                                   .fromOpaque(ctx).takeUnretainedValue()
                               me.received(UnsafeRawPointer(data), len, family)
                           },
                           { ctx, name, info in
                               guard let ctx, let name else { return }
                               let me = Unmanaged<OpenVPNTunnelAdapter>
                                   .fromOpaque(ctx).takeUnretainedValue()
                               me.event(String(cString: name),
                                        info.map { String(cString: $0) } ?? "")
                           },
                           { ctx, json in
                               guard let ctx, let json else { return }
                               let me = Unmanaged<OpenVPNTunnelAdapter>
                                   .fromOpaque(ctx).takeUnretainedValue()
                               me.pushed(String(cString: json))
                           },
                           { _, _ in
                               // OpenVPN 3's log stream is verbose and can carry
                               // the relay's own text; it is not forwarded into
                               // diagnostics, where it would be attacker-influenced
                               // content in a buffer the user reads.
                           },
                           ctx)
        }

        guard let created else {
            fail(.allRungsFailed)
            return
        }
        handle = created

        guard sweep_ovpn_start(created) == 0 else {
            fail(.allRungsFailed)
            return
        }
    }

    public func send(packets: [Data], protocols: [NSNumber]) {
        guard let handle else { return }
        for packet in packets where !packet.isEmpty {
            packet.withUnsafeBytes { raw in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
                sweep_ovpn_send(handle, base, raw.count)
            }
        }
    }

    public func stop() {
        transport?.stop()
        transport = nil
        guard let handle else { return }
        sweep_ovpn_stop(handle)
    }

    public func reassert() {
        guard let handle else { return }
        // `finished` latches so the several events OpenVPN 3 emits on the way
        // down are reported once. A reconnect starts a new attempt, so the latch
        // has to be released or that attempt's failure is swallowed and the
        // coordinator waits forever on an adapter that is already dead.
        lock.lock()
        finished = false
        lastRxSample = nil
        lock.unlock()
        sweep_ovpn_reconnect(handle)
    }

    /// OpenVPN has no periodic handshake the way WireGuard does — the TLS
    /// session is established once and rekeyed on the server's schedule — so
    /// this reports session age rather than inventing a handshake age.
    public var lastHandshakeAgeSeconds: Int64 {
        lock.lock(); defer { lock.unlock() }
        guard let connectedAt else { return -1 }
        return Int64(Date().timeIntervalSince(connectedAt))
    }

    /// Alive if inbound bytes advanced since the previous sample, or if the
    /// session is still inside its opening grace period. The default
    /// implementation would call a perfectly healthy OpenVPN session dead the
    /// moment it had been up for `handshakeStaleAfter` seconds, because the only
    /// number it has to go on is one that never stops growing.
    public func sampleLiveness() -> Bool {
        let now = Date()
        let rx = transferred.rx

        lock.lock()
        let since = connectedAt
        let previous = lastRxSample
        lastRxSample = (rx, now)
        lock.unlock()

        // Not connected yet: nothing to judge, and the provider's handshake
        // deadline is what bounds this phase.
        guard let since else { return false }
        if let previous, rx > previous.bytes { return true }
        return now.timeIntervalSince(since) < TunnelLiveness.openVPNQuietGrace
    }

    public var transferred: (tx: UInt64, rx: UInt64) {
        guard let handle else { return (0, 0) }
        var tx: UInt64 = 0
        var rx: UInt64 = 0
        sweep_ovpn_stats(handle, &tx, &rx)
        return (tx, rx)
    }

    // MARK: - Callbacks from the shim

    private func received(_ bytes: UnsafeRawPointer, _ len: Int, _ family: Int32) {
        guard len > 0 else { return }
        let data = Data(bytes: bytes, count: len)
        let proto = NSNumber(value: family == AF_INET6 ? AF_INET6 : AF_INET)
        onInbound?([data], [proto])
    }

    private func pushed(_ json: String) {
        guard let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode(PushedTunnelSettings.self, from: data)
        else {
            fail(.configurationInvalid)
            return
        }
        // Remote input: validated before it can become tunnel settings.
        guard let valid = try? decoded.validated() else {
            fail(.configurationInvalid)
            return
        }
        lock.lock()
        _pushed = valid
        lock.unlock()
    }

    private func event(_ name: String, _ info: String) {
        // The OpenVPN core's own state names are the only account of where a
        // handshake stopped. Without them a stalled connect is indistinguishable
        // from a dead relay, and both look like a 45-second timeout.
        Self.log.notice("ovpn \(name, privacy: .public) \(Diagnostics.scrub(info), privacy: .public)")
        Diagnostics.shared.record("ovpn", "\(name) \(info)")
        switch name {
        case "CONNECTED":
            // Only now is there a tunnel: the session is up *and* the push has
            // been validated. Without an address there is nothing to configure,
            // so this is a failure rather than a connection.
            guard pushedSettings?.hasUsableAddress == true else {
                fail(.configurationInvalid)
                return
            }
            lock.lock()
            connectedAt = Date()
            lock.unlock()
            onAuthenticated?()

        case "AUTH_FAILED", "CERT_VERIFY_FAIL", "TLS_VERSION_MIN":
            fail(.authenticationFailed)

        case "CLIENT_HALT", "CONNECTION_TIMEOUT", "CONNECT_FAILED",
             "CONFIG_ERROR", "TRANSPORT_ERROR", "DISCONNECTED":
            // The coordinator treats any of these as "this rung did not work"
            // and walks on; none of them is a reason to claim a tunnel.
            fail(.allRungsFailed)

        default:
            break
        }
    }

    /// Report a terminal outcome exactly once — OpenVPN 3 emits several events
    /// on the way down, and the coordinator treats each failure as a reason to
    /// walk the ladder.
    private func fail(_ kind: TunnelErrorKind) {
        lock.lock()
        if finished { lock.unlock(); return }
        finished = true
        lock.unlock()
        onFailure?(kind)
    }
}
#endif
