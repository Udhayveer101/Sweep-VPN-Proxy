import Foundation
import NetworkExtension
import Network
import SweepVPNCore

/// Shared provider logic for iOS and macOS. The platform targets subclass this
/// and add nothing but packaging.
///
/// Order of operations is the security-critical part:
///   1. install the blackhole tunnel settings (default route, forwarding off)
///   2. race/walk the protocol ladder
///   3. only once a peer *authenticates*, install the real settings and start
///      reading from packetFlow
/// The start completion handler is never called before step 3, so the OS holds
/// traffic rather than falling back to the physical interface.
open class SweepPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    /// All mutable provider state is confined to this serial queue; adapter and
    /// path-monitor callbacks hop onto it before touching anything.
    private let stateQueue = DispatchQueue(label: "vpn.sweep.provider")

    public let diagnostics = Diagnostics.shared
    /// The provider's own transitions, journalled. `StateMachine` has always
    /// taken a log closure and this was the default no-op, so the authoritative
    /// state machine — the one the app only ever sees a mirror of — left no
    /// record at all. A tunnel that sits in `handshaking` until the deadline
    /// fires is indistinguishable from one that never started without it.
    public private(set) var machine = StateMachine { old, new in
        Diagnostics.shared.record("providerState", "\(old.logLabel) → \(new.logLabel)")
    }
    public private(set) var policy = SecurityPolicy()
    public private(set) var preference: ProtocolPreference = .automatic

    private var coordinator: ConnectionCoordinator?
    private var catalog = ServerCatalog()
    private var memoryStore: NetworkMemoryStore?
    private var fingerprint: String?
    private var connectedSince: Date?
    private var pathMonitor: NWPathMonitor?
    private var startCompletion: ((Error?) -> Void)?
    private var readingPackets = false
    /// Always false today, and correctly so. `PostQuantum.Exchange` and
    /// `WireGuardAdapter.applyPostQuantumPSK` both exist, but nothing performs the
    /// in-tunnel ML-KEM exchange that would produce the PSK — and the third-party
    /// relays currently in the catalog could not answer it anyway. Flipping this
    /// to true would put a post-quantum glyph on a tunnel that has no PQ material.
    private var pqActive = false
    private var healthTimer: DispatchSourceTimer?
    /// Previous inbound byte count and when it was read, for the rate.
    private var lastRxSample: (bytes: UInt64, at: Date)?
    private var probeTimer: DispatchSourceTimer?
    private let prober = ServerProber()
    private var handshakeDeadline: DispatchWorkItem?
    private var lastSignals = NetworkSignals()
    /// Tells roaming apart from our own tunnel appearing. See `handlePathChange`.
    private var roaming = RoamingDetector()
    /// Slows the fail -> on-demand-restart -> fail cycle when nothing will
    /// authenticate. See `StartBackoff`.
    private var backoff = StartBackoff()

    /// If no peer authenticates in this long we fail closed with a named error
    /// rather than sitting blocked and silent.
    private static let handshakeTimeout: TimeInterval = 45
    private static let healthInterval: TimeInterval = 10
    private static let probeInterval: TimeInterval = 900

    /// macOS only: the tunnel publishes its state here so the content-filter
    /// extension (kill-switch layer 2) knows when to block. On iOS this is nil.
    open var filterStateStore: FilterStateStore? { nil }

    /// Injected by the platform target: where secrets live. `nil` means the
    /// keychain or the pinned key is unavailable — a fail-closed error, never a
    /// reason to bring up an unauthenticated tunnel.
    open var configStore: ConfigStore? { nil }
    open var appBuild: Int { 1 }
    /// Where the failed-start streak is kept between extension launches.
    /// Platform targets point this at the shared app group.
    open var backoffStore: StartBackoffStore? { nil }
    /// Where the user's chosen public relay is kept, if the platform target
    /// supports the OpenVPN rungs.
    open var relayStore: RelaySelectionStore? { nil }
    /// How long each relay has held a tunnel, folded into `Server.reliability`
    /// so the pool is ordered by what survives rather than only by what is fast.
    open var relayStabilityStore: RelayStabilityStore? { RelayStabilityStore(appGroup: appGroup) }
    /// How much bandwidth each relay has actually delivered, folded into
    /// `Server.load` so the pool is ordered by the thing the user notices.
    open var relayThroughputStore: RelayThroughputStore? { RelayThroughputStore(appGroup: appGroup) }
    /// The shared app group, for the settings that live outside the keychain.
    open var appGroup: String { AppGroupID.resolved }

    // MARK: - Lifecycle

    open override func startTunnel(options: [String: NSObject]?,
                                   completionHandler: @escaping (Error?) -> Void) {
        startCompletion = completionHandler
        diagnostics.record("startTunnel")
        // Inherit the streak from the previous (now dead) extension process.
        backoff = (backoffStore?.load() ?? StartBackoff()).effective()

        let queue = stateQueue
        // 1. Fail closed first, always.
        // The Worker has to stay reachable through the blackhole, or the tunnel
        // blocks the very connection it needs to come up.
        #if os(macOS)
        let relayTunnel = RelayTunnelSettings.load(appGroup: appGroup)
        let reachable = relayTunnel.enabled ? relayTunnel.workerAddresses(appGroup: appGroup) : []
        #else
        let reachable: Set<String> = []   // the Worker leg is macOS-only
        #endif
        diagnostics.record("blackhole", "excluding \(reachable.count) worker address(es)")
        applyPlan(policy.blackholePlan(reachableHosts: reachable)) { [weak self] error in
            queue.async {
                guard let self else { return }
                if let error { return self.fail(.internalFailure, error, completionHandler) }
                self.machine.transition(to: .connecting(rung: self.plannedRung()))
                do {
                    try self.beginConnection()
                } catch {
                    // Not every startup failure is a bad signature. Reporting
                    // them all as one sent every investigation to the config
                    // path, when the usual cause is an absent store or relay.
                    self.fail(Self.kind(for: error), error, completionHandler)
                }
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason,
                                 completionHandler: @escaping () -> Void) {
        diagnostics.record("stopTunnel", "\(reason.rawValue)")
        stateQueue.async { [weak self] in
            self?.publishFilterState(up: false, server: nil)
            self?.teardown()
            self?.machine.transition(to: .disconnected)
            completionHandler()
        }
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        diagnostics.record("sleep")
        stateQueue.async { [weak self] in
            self?.machine.transition(to: .reasserting)
            completionHandler()
        }
    }

    open override func wake() {
        diagnostics.record("wake")
        stateQueue.async { [weak self] in
            // Re-validate the peer before any packet is forwarded again.
            self?.machine.transition(to: .reasserting)
            self?.coordinator?.reassert()
        }
    }

    private func teardown() {
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        healthTimer?.cancel(); healthTimer = nil
        probeTimer?.cancel(); probeTimer = nil
        pathMonitor?.cancel(); pathMonitor = nil
        persistNetworkMemory()
        coordinator?.stop()
        coordinator = nil
    }

    // MARK: - Connection

    private func beginConnection() throws {
        guard let store = configStore else { throw ConfigError.badSignature }

        // A chosen public relay is its own mode. There is no signed bundle
        // behind it — that is the whole point of the separation — so it must
        // not be gated on one, and it pins exactly the relay the user picked
        // rather than racing a ladder the relay is not part of.
        // The whole pool, not just the pin: a relay that drops mid-session has
        // to have somewhere to hand over to, or the tunnel dies with it.
        // Two independent measures, both from live sessions rather than from
        // what the operator advertises: how long the relay lasts, and how fast
        // it actually was while it did.
        var relayPool = relayStore?.loadAll() ?? []
        if let stability = relayStabilityStore { relayPool = stability.applied(to: relayPool) }
        if let throughput = relayThroughputStore { relayPool = throughput.applied(to: relayPool) }
        let relay = relayPool.first
        let bundle = try store.loadBundle()
        guard bundle != nil || relay != nil else { throw ConfigError.noServers }

        catalog = relay == nil
            ? ServerCatalog(servers: bundle?.servers ?? [], rung: .wireGuardUDP)
            : ServerCatalog(servers: relayPool,
                            rungs: Set(relayPool.flatMap { $0.endpoints.map(\.rung) }))
        let memoryStore = NetworkMemoryStore(store: store.store)
        self.memoryStore = memoryStore
        let fingerprint = currentFingerprint(store: store)
        self.fingerprint = fingerprint
        let memory = fingerprint.map { memoryStore.memory(for: $0) } ?? NetworkMemory()

        let enabled: Set<ProtocolRung>
        let activePreference: ProtocolPreference
        if let relay {
            // Only the rungs this relay actually offers, and forced, because
            // Automatic deliberately will not select an OpenVPN rung.
            _ = relay
            enabled = Set(relayPool.flatMap { $0.endpoints.map(\.rung) })
                .intersection(AdapterFactory.implementedRungs)
            activePreference = enabled.min().map { ProtocolPreference.forced($0) } ?? preference
        } else {
            enabled = Set(bundle?.enabledRungs ?? []).intersection(AdapterFactory.implementedRungs)
            activePreference = preference
        }
        guard !enabled.isEmpty else { throw AdapterFactoryError.rungNotImplemented(.wireGuardUDP) }
        // The three facts that decide everything that follows. Without them a
        // failed run cannot be told apart from a run that was never going to
        // work: a pinned relay and a signed bundle walk completely different
        // ladders, and "allRungsFailed" means nothing until you know which
        // rungs were even on the list.
        diagnostics.record("mode", relay != nil ? "pinned relay" : "signed bundle")
        diagnostics.record("candidates",
                           "\(catalog.servers.count) server(s), rungs: "
                           + enabled.sorted().map(\.shortName).joined(separator: ", "))
        let engine = AutoModeEngine(preference: activePreference, enabledRungs: enabled)

        // Operators that register a key per config ship it in the bundle; our
        // own machines all use the one key generated on this device.
        // OpenVPN relays authenticate with the profile's own certificate, so
        // there is no device key involved; only the WireGuard rungs need one.
        let deviceKey = relay == nil
            ? try store.devicePrivateKey().rawRepresentation.base64EncodedString()
            : ""

        let signals = currentSignals()
        lastSignals = signals
        let keepalive = KeepalivePolicy.interval(isExpensive: signals.isExpensive,
                                                 isLowPowerMode: signals.isLowPowerMode,
                                                 userActive: true)

        let coordinator = ConnectionCoordinator(
            engine: engine, catalog: catalog, memory: memory,
            build: { rung, server in
                try AdapterFactory.make(rung: rung, server: server,
                                        privateKeyBase64: server.devicePrivateKey ?? deviceKey,
                                        presharedKeyBase64: nil, keepalive: keepalive)
            },
            callbacks: .init(
                onAuthenticated: { [weak self] adapter, server in
                    self?.stateQueue.async { self?.peerAuthenticated(adapter: adapter, server: server) }
                },
                onInbound: { [weak self] packets, protocols in
                    self?.deliverInbound(packets, protocols)
                },
                onExhausted: { [weak self] kind in
                    self?.stateQueue.async { self?.fail(kind, nil, self?.startCompletion) }
                },
                onEvent: { [weak self] kind, detail in
                    self?.diagnostics.record(kind, detail)
                },
                onRelayLifetime: { [weak self] id, seconds in
                    self?.relayStabilityStore?.record(id, lasted: seconds)
                }))
        self.coordinator = coordinator

        machine.transition(to: .handshaking(rung: enabled.min() ?? .wireGuardUDP))
        armHandshakeDeadline()
        coordinator.start(signals: signals)
        startPathMonitor()
        // Relays are never probed here: probing one means dialling it directly,
        // outside the Worker, in plaintext OpenVPN — the exact signature this
        // gateway resets (measured: instant RST on every direct attempt). The
        // app ranks them from outside the tunnel instead.
        if relay == nil, catalog.servers.count > 1 { startProbing() }
    }

    /// The rung the next attempt will use, for honest state reporting before the
    /// coordinator exists. A pinned relay decides it; otherwise the ladder does.
    private func plannedRung() -> ProtocolRung {
        if let relay = relayStore?.load(),
           let rung = Set(relay.endpoints.map(\.rung))
               .intersection(AdapterFactory.implementedRungs).min() {
            return rung
        }
        return .wireGuardUDP
    }

    private func armHandshakeDeadline() {
        // Named in the log with its duration, so a run that stops producing
        // lines has a stated deadline to be read against rather than looking
        // like it could still come back at any moment.
        diagnostics.record("handshakeDeadline", "\(Int(Self.handshakeTimeout))s to authenticate")
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.machine.state.forwardingAllowed else { return }
            self.diagnostics.record("handshakeDeadlineExpired",
                                    "no peer authenticated in \(Int(Self.handshakeTimeout))s")
            self.fail(.allRungsFailed, nil, self.startCompletion)
            self.coordinator?.stop()
        }
        handshakeDeadline?.cancel()
        handshakeDeadline = deadline
        stateQueue.asyncAfter(deadline: .now() + Self.handshakeTimeout, execute: deadline)
    }

    /// The one place that opens the blackhole.
    private func peerAuthenticated(adapter: TunnelAdapter, server: Server) {
        guard let endpoint = server.endpoints.first(where: { $0.rung == adapter.rung })
                ?? server.endpoints.first else { return }
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        diagnostics.record("authenticated", adapter.rung.shortName)
        // A tunnel that came up clears the streak: the next failure, whenever
        // it comes, gets a fast retry again.
        backoff = backoff.recordingSuccess()
        backoffStore?.save(backoff)

        let queue = stateQueue
        // OpenVPN assigns the address, resolvers and routes in PUSH_REPLY, so
        // for those rungs the plan comes from what the relay sent rather than
        // from the server record, which carries none of it.
        let plan = adapter.pushedSettings.map {
            policy.connectedPlan(server: server, endpoint: endpoint, pushed: $0)
        } ?? policy.connectedPlan(server: server, endpoint: endpoint)

        applyPlan(plan) { [weak self] error in
            queue.async {
                guard let self else { return }
                if let error { return self.fail(.internalFailure, error, self.startCompletion) }
                self.machine.transition(to: .connected(rung: adapter.rung, server: server.id))
                // A reason kept past the connect that disproved it is just a
                // lie with a timestamp on it.
                TunnelFailureStore(appGroup: self.appGroup).clear()
                self.connectedSince = Date()
                self.publishFilterState(up: true, server: server)
                self.persistNetworkMemory()
                self.startReadingPackets()
                self.startHealthMonitor()
                self.startCompletion?(nil)
                self.startCompletion = nil
            }
        }
    }

    private func deliverInbound(_ packets: [Data], _ protocols: [NSNumber]) {
        // Refuse to inject anything while the tunnel is not in a forwarding state.
        guard policy.mayForward(state: machine.state) else { return }
        packetFlow.writePackets(packets, withProtocols: protocols)
    }

    private func startReadingPackets() {
        guard !readingPackets else { return }
        readingPackets = true
        readPackets()
    }

    private func readPackets() {
        let queue = stateQueue
        packetFlow.readPackets { [weak self] packets, protocols in
            queue.async {
                guard let self else { return }
                if self.policy.mayForward(state: self.machine.state) {
                    self.coordinator?.send(packets: packets, protocols: protocols)
                }
                // Packets read while blocked are dropped, not queued, not leaked.
                self.readPackets()
            }
        }
    }

    /// Keep the second kill-switch layer in step with the tunnel. Anything other
    /// than "connected" publishes `up: false`, which makes the filter drop.
    private func publishFilterState(up: Bool, server: Server?) {
        guard let filterStateStore else { return }
        var addresses = Set((server?.endpoints ?? []).map(\.host))
        #if os(macOS)
        // When the relay tunnel is on, the flow that actually leaves this
        // machine goes to the Worker, not to the relay. Allow-listing only the
        // relay leaves the filter dropping the connection the tunnel needs to
        // come up at all, which fails closed with no way back.
        let relayTunnel = RelayTunnelSettings.load(appGroup: appGroup)
        // Cache-first, like the blackhole's exclusion list. Resolving here
        // instead returned nothing — the lookup runs inside a tunnel whose
        // default route we already own — so the filter was published with an
        // empty allow-list while the kill switch was armed. It then dropped the
        // extension's own connection to the Worker: no reset, no error, just a
        // flow that never completed, which surfaced as OpenVPN retrying every
        // ten seconds until the race timed out.
        if relayTunnel.enabled {
            addresses.formUnion(relayTunnel.workerAddresses(appGroup: appGroup))
            // The Worker's *name*, alongside its addresses.
            //
            // `NEFilterSocketFlow.remoteFlowEndpoint` reports what the socket
            // was given, and the transport dials a URL — so from macOS 15 on
            // the flow arrives as `.name("…workers.dev")` and never as an
            // address. Matching an address set against it always failed, the
            // policy fell through to "the tunnel is not up yet", and the filter
            // dropped the one connection that would have brought it up.
            // Measured: `waiting(POSIX 53: Software caused connection abort)`
            // on every dial, which is what a filter `.drop()` looks like from
            // the far side of the socket.
            if let host = relayTunnel.workerURL.host { addresses.insert(host) }
        }
        #endif
        filterStateStore.write(FilterState(tunnelInterface: nil, tunnelIsUp: up,
                                           serverAddresses: addresses, options: policy.options))
    }

    /// Which error screen a startup failure belongs on.
    static func kind(for error: Error) -> TunnelErrorKind {
        switch error {
        case ConfigError.noServers:
            return .noServersAvailable
        case ConfigError.badSignature:
            // No store at all is an environment fault, not a rejected signature.
            return .internalFailure
        case is AdapterFactoryError:
            return .allRungsFailed
        default:
            return .configurationInvalid
        }
    }

    /// Turns an internal error into a sentence that names the actual cause.
    ///
    /// Every one of these used to surface as "the signed configuration could not
    /// be verified", which sent debugging in the wrong direction every time —
    /// the usual cause is a store or a relay that is simply absent, not a
    /// signature that failed.
    static func explain(_ error: Error) -> String {
        switch error {
        case ConfigError.badSignature:
            return "The app group keychain did not return a config store, so the extension could not read its settings."
        case ConfigError.noServers:
            return "No relay is pinned and no signed bundle is installed, so there was nothing to connect to."
        case ConfigError.malformed:
            return "The stored configuration could not be decoded."
        case ConfigError.expired(let at):
            return "The signed configuration expired on \(at.formatted(date: .abbreviated, time: .shortened))."
        case ConfigError.notYetValid(let at):
            return "The signed configuration is not valid until \(at.formatted(date: .abbreviated, time: .shortened))."
        case ConfigError.rollback(let have, let offered):
            return "The offered configuration (v\(offered)) is older than the installed one (v\(have)), so it was refused."
        case ConfigError.appTooOld(let required, let have):
            return "The configuration needs app build \(required); this build is \(have)."
        case AdapterFactoryError.rungNotImplemented(let rung):
            return "\(rung.displayName) is not built into this app."
        case AdapterFactoryError.noEndpoint(let rung):
            return "The chosen server has no \(rung.displayName) endpoint."
        case AdapterFactoryError.missingCredential(let rung):
            return "The \(rung.displayName) endpoint carries no usable profile or key."
        default:
            return "\(error)"
        }
    }

    private func fail(_ kind: TunnelErrorKind, _ error: Error?, _ completion: ((Error?) -> Void)?) {
        // The kind alone collapses every beginConnection throw into
        // "configurationInvalid", which is the one thing it must not do: a
        // missing keychain store, an empty relay store and an unimplemented
        // rung are three different bugs wearing the same label.
        let detail = error.map(Self.explain) ?? kind.rawValue
        diagnostics.record("failClosed", "\(kind.rawValue) \(detail)")
        // Written where the app can still read it after this process is gone.
        TunnelFailureStore(appGroup: appGroup)
            .save(TunnelFailure(kind: kind.rawValue, detail: detail,
                                rung: (coordinator?.activeRung ?? plannedRung()).displayName,
                                trail: diagnostics.tail(40)))
        publishFilterState(up: false, server: coordinator?.activeServer)
        machine.transition(to: .error(kind))
        persistNetworkMemory()
        startCompletion = nil

        let resolved = error ?? NSError(domain: "vpn.sweep", code: 1)
        guard let completion else { return }

        // The blackhole stays installed while we hold here, so nothing leaks —
        // we are only declining to hand on-demand an instant restart.
        backoff = backoff.recordingFailure()
        backoffStore?.save(backoff)
        let delay = backoff.delay()
        guard delay > 0 else { return completion(resolved) }

        diagnostics.record("startBackoff", "\(Int(delay))s after \(backoff.consecutiveFailures) failures")
        stateQueue.asyncAfter(deadline: .now() + delay) { completion(resolved) }
    }

    // MARK: - Health and measurement

    /// Health is derived from the tunnel itself — handshake age and byte
    /// counters — not from extra probe traffic that would cost battery.
    private func startHealthMonitor() {
        guard healthTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(deadline: .now() + Self.healthInterval, repeating: Self.healthInterval,
                       leeway: .seconds(2))
        timer.setEventHandler { [weak self] in self?.sampleHealth() }
        timer.resume()
        healthTimer = timer
    }

    private func sampleHealth() {
        guard let coordinator, let rung = coordinator.activeRung else { return }
        // Each rung judges its own liveness: handshake freshness for WireGuard,
        // inbound byte movement for OpenVPN, which has no periodic handshake and
        // whose session age only ever grows. Deriving both from one number here
        // marked every healthy OpenVPN tunnel dead at the three-minute mark.
        guard let healthy = coordinator.sampleLiveness() else { return }
        // rttMs is measured by the prober, not inferred here; the engine reads
        // only lossFraction and handshakeOK.
        sampleThroughput(coordinator, healthy: healthy)
        let health = LinkHealth(rttMs: 0, lossFraction: healthy ? 0 : 1, handshakeOK: healthy)
        if !healthy, machine.state.forwardingAllowed {
            publishFilterState(up: false, server: coordinator.activeServer)
            machine.transition(to: .degraded(rung: rung, reason: .handshakeFlapping))
        } else if healthy, case .degraded = machine.state, let server = coordinator.activeServer {
            machine.transition(to: .connected(rung: rung, server: server.id))
        }
        coordinator.observe(health: health)
    }

    /// Turn the tunnel's own byte counters into a rate for the relay carrying
    /// it. Free — the counters are already there for liveness — and it is the
    /// only throughput figure that reflects the whole chain the user is
    /// actually on, rather than what a relay advertises or how fast it answers
    /// a TCP handshake.
    ///
    /// Only inbound: it is what a download feels like, and the outbound side of
    /// a browsing session is mostly ACKs.
    private func sampleThroughput(_ coordinator: ConnectionCoordinator, healthy: Bool) {
        let rx = coordinator.transferred.rx
        let now = Date()
        defer { lastRxSample = (rx, now) }
        guard let previous = lastRxSample, let relay = coordinator.activeServer else { return }
        let elapsed = now.timeIntervalSince(previous.at)
        // A counter that went backwards means a new session on a new relay;
        // there is no rate to read across that boundary.
        guard elapsed > 0, rx >= previous.bytes else { return }
        // A window in which the tunnel was not working is not a measurement of
        // the relay. This guard was missing, so a dead Worker leg scored ~0 and
        // the EWMA in `RelayThroughputStore` demoted a relay for the crime of
        // being attached when our own leg died.
        guard healthy else { return }
        let delta = rx - previous.bytes
        // Nor is an idle window. Recording the zero poisons the ranking with a
        // number about the *user*, not the relay: a session spent reading one
        // page would permanently rank a good relay below an untried one.
        guard delta >= Self.throughputSampleFloor else { return }
        relayThroughputStore?.record(relay.id, bytesPerSecond: Double(delta) / elapsed)
    }

    /// Bytes that have to arrive in a health interval before the window says
    /// anything about the relay. Deliberately low — this separates "nothing
    /// happened" from "something happened", not fast from slow.
    static let throughputSampleFloor: UInt64 = 64 * 1024

    /// Keep the server ranking honest: re-measure occasionally and on network
    /// change so "fastest" means fastest *here, now*.
    private func startProbing() {
        probeServers()
        guard probeTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(deadline: .now() + Self.probeInterval, repeating: Self.probeInterval,
                       leeway: .seconds(30))
        timer.setEventHandler { [weak self] in self?.probeServers() }
        timer.resume()
        probeTimer = timer
    }

    private func probeServers() {
        let targets = catalog.probeTargets(limit: 5)
        guard !targets.isEmpty else { return }
        let rung = catalog.rung
        prober.probe(targets, rung: rung) { [weak self] results in
            self?.stateQueue.async {
                guard let self else { return }
                for result in results { self.catalog.record(result.probe, for: result.id) }
                self.diagnostics.record("probed", "\(results.count) servers")
            }
        }
    }

    private func persistNetworkMemory() {
        guard let fingerprint, let memoryStore, let coordinator else { return }
        let learned = coordinator.updatedMemory
        memoryStore.update(fingerprint) { $0 = learned }
    }

    // MARK: - Roaming

    private func startPathMonitor() {
        let queue = stateQueue
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let expensive = path.isExpensive
            let satisfied = path.status == .satisfied
            let constrained = path.isConstrained
            // The interfaces that are not ours. `.other` is the utun family, so
            // excluding it is what makes this signature blind to the tunnel we
            // are ourselves installing.
            let signature = path.availableInterfaces
                .filter { $0.type != .other }
                .map { "\($0.name):\($0.type)" }
                .sorted()
                .joined(separator: ",")
            queue.async {
                self?.handlePathChange(satisfied: satisfied, expensive: expensive,
                                       constrained: constrained, signature: signature)
            }
        }
        monitor.start(queue: DispatchQueue(label: "vpn.sweep.path"))
        pathMonitor = monitor
    }

    /// Roaming. Only a *different* underlying network is roaming.
    ///
    /// This used to reassert on every path update, which is a reconnect storm
    /// rather than a roaming handler: bringing the tunnel up changes the path,
    /// so installing our own settings triggered a reassert, which redialled
    /// OpenVPN through a fresh Worker socket, which changed the path again.
    /// Measured on the 2026-09-04 journal — the session never held a route for
    /// more than about ten seconds, and because `.reasserting` gates forwarding,
    /// every packet in between was dropped. That is the "connected but no
    /// internet" the user saw, and no amount of relay or transport tuning could
    /// have shown through it.
    ///
    /// So: act when the set of non-tunnel interfaces actually changes, and
    /// otherwise record the update and leave the tunnel alone.
    private func handlePathChange(satisfied: Bool, expensive: Bool, constrained: Bool,
                                  signature: String) {
        lastSignals = NetworkSignals(isExpensive: expensive,
                                     isLowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
                                     isConstrained: constrained)

        switch roaming.update(satisfied: satisfied, signature: signature) {
        case .lost:
            diagnostics.record("pathLost")
            publishFilterState(up: false, server: coordinator?.activeServer)
            machine.transition(to: .reasserting)
        case .first:
            diagnostics.record("pathChanged", "first sighting: \(signature)")
        case .unchanged:
            diagnostics.record("pathChanged", "same network — keeping the tunnel")
        case .roamed(let from, let to):
            diagnostics.record("pathChanged", "\(from) → \(to)")
            machine.transition(to: .reasserting)
            coordinator?.reassert()   // re-handshake; forwarding stays gated
            probeServers()            // the fastest server on Wi-Fi is rarely the fastest on cellular
        }
    }

    private func currentSignals() -> NetworkSignals {
        NetworkSignals(isExpensive: lastSignals.isExpensive,
                       isLowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
                       isConstrained: lastSignals.isConstrained)
    }

    private func currentFingerprint(store: ConfigStore) -> String? {
        guard let secret = try? store.fingerprintSecret() else { return nil }
        // SSID is unavailable to an extension without extra entitlements; the
        // interface type plus the tunnel's local address is a stable-enough key.
        return NetworkFingerprint.key(deviceSecret: secret, ssid: nil, gatewayMAC: nil,
                                      dnsSuffix: nil,
                                      interface: lastSignals.isExpensive ? "cellular" : "wifi")
    }

    // MARK: - Settings

    private func applyPlan(_ plan: TunnelPlan, completion: @escaping (Error?) -> Void) {
        setTunnelNetworkSettings(TunnelSettingsMapper.settings(for: plan), completionHandler: completion)
    }

    // MARK: - IPC

    open override func handleAppMessage(_ messageData: Data,
                                        completionHandler: ((Data?) -> Void)?) {
        guard let message = try? IPCCodec.decode(AppToProvider.self, messageData) else {
            completionHandler?(nil); return
        }
        stateQueue.async { [weak self] in
            guard let self else { return completionHandler?(nil) ?? () }
            switch message {
            case .getStatus:
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            case .setPreference(let p):
                self.preference = p
                self.diagnostics.record("preferenceChanged", p.displayName)
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            case .setSecurityOptions(let o):
                self.policy = SecurityPolicy(options: o)
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            case .reconnect:
                self.coordinator?.reassert()
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            case .exportDiagnostics:
                completionHandler?(try? IPCCodec.encode(
                    ProviderToApp.diagnostics(self.diagnostics.snapshot())))
            case .getServers:
                completionHandler?(try? IPCCodec.encode(
                    ProviderToApp.servers(self.catalog.rankedSnapshot())))
            case .selectServer(let id):
                self.diagnostics.record("serverSelected", id)
                self.coordinator?.reassert()
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            case .relaySelectionChanged:
                // The app wrote a new relay to the shared store. Rebuild the
                // connection against it rather than reasserting the old one,
                // which would keep the previous relay's session alive.
                self.diagnostics.record("relaySelectionChanged")
                self.teardown()
                self.machine.transition(to: .reasserting)
                do { try self.beginConnection() }
                catch { self.fail(.noServersAvailable, error, nil) }
                completionHandler?(try? IPCCodec.encode(ProviderToApp.status(self.status())))
            }
        }
    }

    private func status() -> ProviderStatus {
        let rung = coordinator?.activeRung
        let server = coordinator?.activeServer
        return ProviderStatus(state: machine.state,
                              serverName: server?.name,
                              rung: rung,
                              connectedSince: connectedSince,
                              rttMs: server.flatMap { catalog.probes[$0.id]?.rttMs },
                              killSwitchArmed: policy.includeAllNetworks,
                              pqHybridActive: pqActive,
                              // -1 means "never handshaked"; keep that distinct
                              // from "handshaked 0 seconds ago".
                              handshakeAgeSeconds: coordinator.map { $0.handshakeAgeSeconds }
                                  .flatMap { $0 >= 0 ? $0 : nil },
                              bytesSent: coordinator?.transferred.tx ?? 0,
                              bytesReceived: coordinator?.transferred.rx ?? 0)
    }
}

/// Maps the platform-neutral plan onto NEPacketTunnelNetworkSettings.
public enum TunnelSettingsMapper {
    public static func settings(for plan: TunnelPlan) -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: plan.tunnelRemoteAddress)
        s.mtu = NSNumber(value: plan.mtu)

        let v4 = NEIPv4Settings(addresses: [plan.ipv4Address], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = plan.ipv4Routes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: mask4($0.prefix))
        }
        v4.excludedRoutes = plan.ipv4ExcludedRoutes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: mask4($0.prefix))
        }
        s.ipv4Settings = v4

        // IPv6 is either routed into the tunnel or blackholed at an address we
        // own. It is never left to the physical interface.
        let v6Address = plan.ipv6Address ?? (plan.ipv6Blocked ? "fd00:5:e:e:p::1" : nil)
        if let v6Address, !plan.ipv6Routes.isEmpty {
            let v6 = NEIPv6Settings(addresses: [v6Address], networkPrefixLengths: [128])
            v6.includedRoutes = plan.ipv6Routes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
            }
            v6.excludedRoutes = plan.ipv6ExcludedRoutes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
            }
            s.ipv6Settings = v6
        }

        // An empty server list is not "resolve nothing", it is "do not touch
        // the resolver" — the pre-connect blackhole leaves DNS alone so the
        // tunnel can look up its own uplink. Installing NEDNSSettings with no
        // servers would instead leave the interface with a resolver that
        // answers nothing.
        if !plan.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: plan.dnsServers)
            dns.matchDomains = plan.dnsMatchDomains
            dns.matchDomainsNoSearch = false
            s.dnsSettings = dns
        }
        return s
    }

    static func mask4(_ prefix: Int) -> String {
        let m = prefix == 0 ? 0 : UInt32.max << (32 - UInt32(prefix))
        return "\((m >> 24) & 255).\((m >> 16) & 255).\((m >> 8) & 255).\(m & 255)"
    }
}
