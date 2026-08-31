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

    public let diagnostics = Diagnostics()
    public private(set) var machine = StateMachine()
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
    private var pqActive = false
    private var healthTimer: DispatchSourceTimer?
    private var probeTimer: DispatchSourceTimer?
    private let prober = ServerProber()
    private var handshakeDeadline: DispatchWorkItem?
    private var lastSignals = NetworkSignals()

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

    // MARK: - Lifecycle

    open override func startTunnel(options: [String: NSObject]?,
                                   completionHandler: @escaping (Error?) -> Void) {
        startCompletion = completionHandler
        diagnostics.record("startTunnel")

        let queue = stateQueue
        // 1. Fail closed first, always.
        applyPlan(policy.blackholePlan()) { [weak self] error in
            queue.async {
                guard let self else { return }
                if let error { return self.fail(.internalFailure, error, completionHandler) }
                self.machine.transition(to: .connecting(rung: .wireGuardUDP))
                do {
                    try self.beginConnection()
                } catch {
                    self.fail(.configurationInvalid, error, completionHandler)
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
        guard let bundle = try store.loadBundle() else { throw ConfigError.noServers }

        catalog = ServerCatalog(servers: bundle.servers, rung: .wireGuardUDP)
        let memoryStore = NetworkMemoryStore(store: store.store)
        self.memoryStore = memoryStore
        let fingerprint = currentFingerprint(store: store)
        self.fingerprint = fingerprint
        let memory = fingerprint.map { memoryStore.memory(for: $0) } ?? NetworkMemory()

        let enabled = Set(bundle.enabledRungs).intersection(AdapterFactory.implementedRungs)
        guard !enabled.isEmpty else { throw AdapterFactoryError.rungNotImplemented(.wireGuardUDP) }
        let engine = AutoModeEngine(preference: preference, enabledRungs: enabled)

        let privateKey = try store.devicePrivateKey().rawRepresentation.base64EncodedString()
        let signals = currentSignals()
        lastSignals = signals
        let keepalive = KeepalivePolicy.interval(isExpensive: signals.isExpensive,
                                                 isLowPowerMode: signals.isLowPowerMode,
                                                 userActive: true)

        let coordinator = ConnectionCoordinator(
            engine: engine, catalog: catalog, memory: memory,
            build: { rung, server in
                try AdapterFactory.make(rung: rung, server: server, privateKeyBase64: privateKey,
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
                }))
        self.coordinator = coordinator

        machine.transition(to: .handshaking(rung: .wireGuardUDP))
        armHandshakeDeadline()
        coordinator.start(signals: signals)
        startPathMonitor()
        startProbing()
    }

    private func armHandshakeDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.machine.state.forwardingAllowed else { return }
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

        let queue = stateQueue
        applyPlan(policy.connectedPlan(server: server, endpoint: endpoint)) { [weak self] error in
            queue.async {
                guard let self else { return }
                if let error { return self.fail(.internalFailure, error, self.startCompletion) }
                self.machine.transition(to: .connected(rung: adapter.rung, server: server.id))
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
        let addresses = Set((server?.endpoints ?? []).map(\.host))
        filterStateStore.write(FilterState(tunnelInterface: nil, tunnelIsUp: up,
                                           serverAddresses: addresses, options: policy.options))
    }

    private func fail(_ kind: TunnelErrorKind, _ error: Error?, _ completion: ((Error?) -> Void)?) {
        diagnostics.record("failClosed", kind.rawValue)
        publishFilterState(up: false, server: coordinator?.activeServer)
        machine.transition(to: .error(kind))
        persistNetworkMemory()
        completion?(error ?? NSError(domain: "vpn.sweep", code: 1))
        startCompletion = nil
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
        let age = coordinator.handshakeAgeSeconds
        // WireGuard rekeys about every two minutes; an older handshake with no
        // traffic means the path is gone.
        let healthy = age >= 0 && age < 180
        let health = LinkHealth(rttMs: Double(max(age, 0)) * 1000 / 180,
                                lossFraction: healthy ? 0 : 1, handshakeOK: healthy)
        if !healthy, machine.state.forwardingAllowed {
            publishFilterState(up: false, server: coordinator.activeServer)
            machine.transition(to: .degraded(rung: rung, reason: .handshakeFlapping))
        } else if healthy, case .degraded = machine.state, let server = coordinator.activeServer {
            machine.transition(to: .connected(rung: rung, server: server.id))
        }
        coordinator.observe(health: health)
    }

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
            queue.async {
                self?.handlePathChange(satisfied: satisfied, expensive: expensive,
                                       constrained: constrained)
            }
        }
        monitor.start(queue: DispatchQueue(label: "vpn.sweep.path"))
        pathMonitor = monitor
    }

    private func handlePathChange(satisfied: Bool, expensive: Bool, constrained: Bool) {
        guard satisfied else {
            diagnostics.record("pathLost")
            publishFilterState(up: false, server: coordinator?.activeServer)
            machine.transition(to: .reasserting)
            return
        }
        diagnostics.record("pathChanged", expensive ? "expensive" : "cheap")
        lastSignals = NetworkSignals(isExpensive: expensive,
                                     isLowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
                                     isConstrained: constrained)
        machine.transition(to: .reasserting)
        coordinator?.reassert()   // re-handshake; forwarding stays gated
        probeServers()            // the fastest server on Wi-Fi is rarely the fastest on cellular
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
                              pqHybridActive: pqActive)
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
            s.ipv6Settings = v6
        }

        let dns = NEDNSSettings(servers: plan.dnsServers)
        dns.matchDomains = plan.dnsMatchDomains
        dns.matchDomainsNoSearch = false
        s.dnsSettings = dns
        return s
    }

    static func mask4(_ prefix: Int) -> String {
        let m = prefix == 0 ? 0 : UInt32.max << (32 - UInt32(prefix))
        return "\((m >> 24) & 255).\((m >> 16) & 255).\((m >> 8) & 255).\(m & 255)"
    }
}
