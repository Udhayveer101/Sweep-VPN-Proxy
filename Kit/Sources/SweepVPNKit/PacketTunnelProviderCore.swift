import Foundation
import NetworkExtension
import Network
import SweepVPNCore

/// Shared provider logic for iOS and macOS. The platform targets subclass
/// `SweepPacketTunnelProvider` and add nothing but packaging.
///
/// Order of operations is the security-critical part:
///   1. install the blackhole tunnel settings (default route, forwarding off)
///   2. start the adapter
///   3. only after the peer authenticates, install the real settings and
///      start reading from packetFlow
/// The completion handler is never called before step 3 succeeds, so the OS
/// holds traffic rather than falling back to the physical interface.
open class SweepPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    /// All mutable provider state is confined to this serial queue; adapter and
    /// path-monitor callbacks hop onto it before touching anything.
    private let stateQueue = DispatchQueue(label: "vpn.sweep.provider")
    public let diagnostics = Diagnostics()
    public private(set) var machine = StateMachine()
    public private(set) var policy = SecurityPolicy()
    private var engine = AutoModeEngine()
    private var adapter: TunnelAdapter?
    private var currentServer: Server?
    private var currentEndpoint: ServerEndpoint?
    private var connectedSince: Date?
    private var pathMonitor: NWPathMonitor?
    private var startCompletion: ((Error?) -> Void)?
    private var readingPackets = false
    private var pqActive = false
    private var handshakeDeadline: DispatchWorkItem?
    /// If the peer never authenticates we must not sit blocked forever with no
    /// explanation: fail closed with a named error so the UI can say why.
    private static let handshakeTimeout: TimeInterval = 30

    /// Injected by the platform target: where secrets live. `nil` means the
    /// keychain or the pinned key is unavailable — that is a fail-closed error,
    /// never a reason to bring up an unauthenticated tunnel.
    open var configStore: ConfigStore? { nil }
    open var appBuild: Int { 1 }

    // MARK: - Lifecycle

    open override func startTunnel(options: [String: NSObject]?,
                                   completionHandler: @escaping (Error?) -> Void) {
        startCompletion = completionHandler
        diagnostics.record("startTunnel")

        // 1. Fail closed first, always.
        let queue = stateQueue
        applyPlan(policy.blackholePlan()) { [weak self] error in
            queue.async {
            guard let self else { return }
            if let error {
                self.fail(.internalFailure, error, completionHandler)
                return
            }
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
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        pathMonitor?.cancel(); pathMonitor = nil
        adapter?.stop(); adapter = nil
        machine.transition(to: .disconnected)
        completionHandler()
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        diagnostics.record("sleep")
        machine.transition(to: .reasserting)
        completionHandler()
    }

    open override func wake() {
        diagnostics.record("wake")
        // Re-validate the peer before any packet is forwarded again.
        machine.transition(to: .reasserting)
        adapter?.reassert()
    }

    // MARK: - Connection

    private func beginConnection() throws {
        guard let store = configStore else { throw ConfigError.badSignature }
        guard let bundle = try store.loadBundle() else {
            throw ConfigError.noServers        // no verified config -> stay blocked
        }
        engine = AutoModeEngine(preference: preference,
                                enabledRungs: Set(bundle.enabledRungs)
                                    .intersection(AdapterFactory.implementedRungs))
        let memory = NetworkMemory()           // per-network memory is loaded by the app facade
        let decision = engine.decideStart(memory: memory, signals: currentSignals(), now: Date())
        let rung: ProtocolRung
        switch decision {
        case .connect(let r): rung = r
        case .race(let rs): rung = rs[0]       // racing is Tier 2; take the preferred rung
        case .failClosed(let kind): throw NSError(domain: "sweep", code: kind.hashValue)
        default: rung = .wireGuardUDP
        }

        guard let server = bundle.servers.first(where: { $0.supports(rung) }),
              let endpoint = server.endpoints.first(where: { $0.rung == rung }) else {
            throw AdapterFactoryError.noEndpoint(rung)
        }
        currentServer = server
        currentEndpoint = endpoint

        let privateKey = try store.devicePrivateKey().rawRepresentation.base64EncodedString()
        let keepalive = KeepalivePolicy.interval(isExpensive: false, isLowPowerMode: false, userActive: true)
        let adapter = try AdapterFactory.make(rung: rung, server: server,
                                              privateKeyBase64: privateKey,
                                              presharedKeyBase64: nil, keepalive: keepalive)
        self.adapter = adapter
        machine.transition(to: .handshaking(rung: rung))

        let queue = stateQueue
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.machine.state.forwardingAllowed else { return }
            self.fail(.allRungsFailed, nil, self.startCompletion)
            self.adapter?.stop()
        }
        handshakeDeadline = deadline
        stateQueue.asyncAfter(deadline: .now() + Self.handshakeTimeout, execute: deadline)

        adapter.start(
            onAuthenticated: { [weak self] in
                queue.async { self?.peerAuthenticated(rung: rung, server: server) }
            },
            onInbound: { [weak self] packets, protos in
                queue.async { self?.deliverInbound(packets, protos) }
            },
            onFailure: { [weak self] kind in
                queue.async { self?.adapterFailed(kind) }
            })
        startPathMonitor()
    }

    /// The one place that opens the blackhole.
    private func peerAuthenticated(rung: ProtocolRung, server: Server) {
        guard let endpoint = currentEndpoint else { return }
        handshakeDeadline?.cancel(); handshakeDeadline = nil
        diagnostics.record("authenticated", rung.displayName)
        let queue = stateQueue
        applyPlan(policy.connectedPlan(server: server, endpoint: endpoint)) { [weak self] error in
            queue.async {
            guard let self else { return }
            if let error { return self.fail(.internalFailure, error, self.startCompletion) }
            self.machine.transition(to: .connected(rung: rung, server: server.id))
            self.engine.noteConnected(rung: rung, now: Date())
            self.connectedSince = Date()
            self.startReadingPackets()
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
                    self.adapter?.send(packets: packets, protocols: protocols)
                }
                // Packets read while blocked are dropped, not queued, not leaked.
                self.readPackets()
            }
        }
    }

    private func adapterFailed(_ kind: TunnelErrorKind) {
        diagnostics.record("adapterFailed", kind.rawValue)
        machine.transition(to: .reconnecting(attempt: 1))
        // Blackhole stays installed; the OS keeps holding traffic.
        adapter?.reassert()
    }

    private func fail(_ kind: TunnelErrorKind, _ error: Error?, _ completion: ((Error?) -> Void)?) {
        diagnostics.record("failClosed", kind.rawValue)
        machine.transition(to: .error(kind))
        completion?(error ?? NSError(domain: "vpn.sweep", code: 1))
        startCompletion = nil
    }

    // MARK: - Roaming

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        let queue = stateQueue
        monitor.pathUpdateHandler = { [weak self] path in
            let expensive = path.isExpensive
            let satisfied = path.status == .satisfied
            queue.async { self?.handlePathChange(satisfied: satisfied, expensive: expensive) }
        }
        monitor.start(queue: DispatchQueue(label: "vpn.sweep.path"))
        pathMonitor = monitor
    }

    private func handlePathChange(satisfied: Bool, expensive: Bool) {
        do {
            guard satisfied else {
                diagnostics.record("pathLost")
                machine.transition(to: .reasserting)
                return
            }
            diagnostics.record("pathChanged", expensive ? "expensive" : "cheap")
            machine.transition(to: .reasserting)
            adapter?.reassert()          // re-handshake, forwarding stays gated
        }
    }

    private func currentSignals() -> NetworkSignals {
        NetworkSignals(isExpensive: false,
                       isLowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled)
    }

    // MARK: - Settings

    private func applyPlan(_ plan: TunnelPlan, completion: @escaping (Error?) -> Void) {
        setTunnelNetworkSettings(TunnelSettingsMapper.settings(for: plan), completionHandler: completion)
    }

    // MARK: - IPC

    public private(set) var preference: ProtocolPreference = .automatic

    open override func handleAppMessage(_ messageData: Data,
                                        completionHandler: ((Data?) -> Void)?) {
        guard let message = try? IPCCodec.decode(AppToProvider.self, messageData) else {
            completionHandler?(nil); return
        }
        switch message {
        case .getStatus:
            let status = ProviderStatus(state: machine.state,
                                        serverName: currentServer?.name,
                                        rung: engine.activeRung,
                                        connectedSince: connectedSince,
                                        rttMs: nil,
                                        killSwitchArmed: policy.includeAllNetworks,
                                        pqHybridActive: pqActive)
            completionHandler?(try? IPCCodec.encode(ProviderToApp.status(status)))
        case .setPreference(let p):
            preference = p
            completionHandler?(try? IPCCodec.encode(ProviderToApp.status(
                ProviderStatus(state: machine.state, serverName: currentServer?.name,
                               rung: engine.activeRung, connectedSince: connectedSince,
                               rttMs: nil, killSwitchArmed: policy.includeAllNetworks,
                               pqHybridActive: pqActive))))
        case .setSecurityOptions(let o):
            policy = SecurityPolicy(options: o)
            completionHandler?(nil)
        case .reconnect:
            adapter?.reassert()
            completionHandler?(nil)
        case .exportDiagnostics:
            completionHandler?(try? IPCCodec.encode(ProviderToApp.diagnostics(diagnostics.snapshot())))
        }
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

        // IPv6 is either routed into the tunnel or blackholed by routing ::/0
        // at an address we own. It is never left to the physical interface.
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
