import Foundation
import NetworkExtension
import SweepVPNCore

/// App-side facade: installs/updates the VPN profile and talks to the provider.
/// The kill-switch flags live here because they are properties of the *profile*,
/// not of the running tunnel.
public final class VPNConfigurator: @unchecked Sendable {
    public let bundleIdentifier: String   // the packet-tunnel extension's bundle id
    public let displayName: String
    private var manager: NETunnelProviderManager?
    /// True only once we have located (or saved) a profile whose provider is *ours*.
    /// Without this we cannot tell "Sweep is disconnected" from "some other VPN owns
    /// the system slot", and the UI ends up reporting a foreign tunnel as our own.
    private var ownsProfile = false

    /// Guards `manager`/`ownsProfile`/`loadTask`. The class is `@unchecked
    /// Sendable` and is called from several tasks at once — the view model's
    /// `onAppear`, its 5-second poll, and a user-driven connect all reach
    /// `loadManager()` — so this state was being read and written concurrently
    /// with no synchronisation at all.
    private let stateLock = NSLock()
    /// The load that is already in flight, so concurrent callers join it rather
    /// than each starting their own. See `loadManager()`.
    ///
    /// It carries no value: `NETunnelProviderManager` is not `Sendable`, so it
    /// cannot travel out of a `Task`. The task's job is to populate `manager`
    /// under the lock, and joiners read it there once the task has settled.
    private var loadTask: Task<Void, Error>?

    public init(bundleIdentifier: String, displayName: String = "Sweep VPN") {
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
    }

    /// Returns *our* profile, never someone else's.
    ///
    /// `loadAllFromPreferences()` returns every packet-tunnel profile on the device.
    /// Adopting `.first` meant we read an unrelated VPN's status as ours and — far
    /// worse — `install()` would overwrite that unrelated VPN's configuration.
    /// Identity is the provider bundle id; nothing else is a safe discriminator.
    ///
    /// # Why this is single-flighted
    ///
    /// The body suspends on `loadAllFromPreferences()` between checking the
    /// cache and filling it. Two callers arriving during that window both saw
    /// an empty cache and both continued — and when no Sweep profile existed
    /// yet, each constructed its *own* `NETunnelProviderManager()`. Two
    /// managers, two `saveToPreferences()`, two profiles: the system VPN menu
    /// then offers to disconnect "Sweep VPN" twice, and only one of them is the
    /// object this app is holding, so the other can neither be shown nor
    /// stopped. Joining the in-flight load closes the window; the check and the
    /// assignment either side of it now happen under the lock with no
    /// suspension between them.
    public func loadManager() async throws -> NETunnelProviderManager {
        // Every critical section here goes through `withState`, which is
        // synchronous: `NSLock` must never be held across a suspension, and the
        // compiler enforces that by refusing `lock()` in an async context.
        if let cached = withState({ manager }) { return cached }

        let task = withState { () -> Task<Void, Error> in
            if let inFlight = loadTask { return inFlight }
            let started = Task { try await self.performLoad() }
            loadTask = started
            return started
        }

        do {
            try await task.value
        } catch {
            // A failed load must not be cached, or every later call replays the
            // same failure against a system that may since have recovered.
            withState { loadTask = nil }
            throw error
        }

        guard let loaded = withState({ manager }) else {
            throw ConfiguratorError.managerUnavailable
        }
        return loaded
    }

    public enum ConfiguratorError: Error {
        /// The shared load reported success but left no manager behind. Only
        /// reachable if `performLoad` is changed to return without assigning.
        case managerUnavailable
    }

    private func performLoad() async throws {
        let existing = try await NETunnelProviderManager.loadAllFromPreferences()
        let ours = Self.selectOurs(from: existing, bundleIdentifier: bundleIdentifier)
        // Counted, because a second profile carrying our provider id is the one
        // thing that would explain the system VPN menu offering to disconnect
        // "Sweep VPN" twice — and it is invisible from anywhere else. `mine`
        // above 1 is a bug; `mine == 0` alongside a non-zero total means we are
        // about to create a profile rather than adopt one.
        let mine = existing.filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == bundleIdentifier
        }.count
        EventLog.shared.record(phase: "profile", level: mine > 1 ? .error : .info,
                               kind: "profileInventory",
                               detail: "\(existing.count) VPN profile(s) on this Mac, \(mine) ours"
                                   + (ours == nil ? " — creating a new one" : " — adopting the existing one"))
        let m = ours ?? NETunnelProviderManager()
        withState {
            ownsProfile = (ours != nil)
            manager = m
        }
    }

    /// Picks the profile whose provider is `bundleIdentifier`, or nil.
    ///
    /// Split out from `loadManager()` so it can be tested without touching system
    /// preferences. A typical Mac carries several unrelated VPN profiles, and the
    /// old `.first` returned whichever the OS listed first.
    static func selectOurs(from managers: [NEVPNManager],
                           bundleIdentifier: String) -> NETunnelProviderManager? {
        managers.lazy.compactMap { $0 as? NETunnelProviderManager }.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == bundleIdentifier
        }
    }

    /// Whether a Sweep profile actually exists in system preferences.
    /// Callers must treat `false` as "not configured", not as "disconnected".
    public var hasInstalledProfile: Bool { withState { ownsProfile } }

    /// The connection object for *our* profile, for scoping `NEVPNStatusDidChange`
    /// observation. Observing with `object: nil` delivers every VPN's transitions.
    public var ourConnection: NEVPNConnection? {
        withState { ownsProfile ? manager?.connection : nil }
    }

    /// Reads the lock-guarded state. These are all called from the main actor
    /// while `loadManager()` may still be resolving on another task, which is
    /// the same race in its read-only form: the UI could observe `ownsProfile`
    /// set against a `manager` that had not been assigned yet.
    private func withState<T>(_ body: () -> T) -> T {
        stateLock.lock(); defer { stateLock.unlock() }
        return body()
    }

    /// Applies the researched kill-switch construction:
    /// on-demand catch-all + includeAllNetworks + excludeLocalNetworks.
    public func install(policy: SecurityPolicy, serverDescription: String) async throws {
        let manager = try await loadManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = bundleIdentifier
        proto.serverAddress = serverDescription

        // `includeAllNetworks` and the Worker bypass cannot both be on.
        //
        // It is the OS-level kill switch, and it is absolute: with it set,
        // excluded routes are ignored and *every* socket goes into the tunnel —
        // including the extension's own connection to the Worker, which is the
        // one thing that has to leave on the physical interface for the tunnel
        // to come up at all. Measured: the exclusion list grew from four
        // addresses to six and changed nothing; the Worker connection sat in
        // `preparing` until the watchdog killed it, on every single attempt.
        //
        // What is given up is only this layer. The blackhole still owns the
        // default route from the moment the tunnel starts and refuses to
        // forward until the peer authenticates, and the content filter still
        // drops every flow that is not on its allow-list — so traffic cannot
        // leak, it simply is not the kernel enforcing it.
        #if os(macOS)
        let relayTunnelOn = RelayTunnelSettings.load(appGroup: AppGroupID.resolved).enabled
        #else
        let relayTunnelOn = false
        #endif
        proto.includeAllNetworks = policy.includeAllNetworks && !relayTunnelOn
        proto.excludeLocalNetworks = policy.excludeLocalNetworks
        if #available(iOS 16.4, macOS 13.3, *) {
            proto.excludeAPNs = false          // keep Apple push inside the tunnel where allowed
        }
        manager.protocolConfiguration = proto
        manager.localizedDescription = displayName
        manager.isEnabled = true

        // A single catch-all connect rule is the App-Store-legal stand-in for
        // always-on: the OS re-arms the tunnel on the first packet from any app.
        manager.isOnDemandEnabled = policy.onDemandEnabled
        manager.onDemandRules = policy.onDemandEnabled ? [NEOnDemandRuleConnect()] : []

        EventLog.shared.record(phase: "profile", kind: "saving",
                               detail: "onDemand=\(policy.onDemandEnabled) "
                                   + "includeAllNetworks=\(proto.includeAllNetworks)"
                                   + (relayTunnelOn ? " (off: the Worker leg needs the wire)" : ""))
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        withState { ownsProfile = true }
        EventLog.shared.record(phase: "profile", kind: "saved", detail: "profile is ours")
    }

    public func start() async throws {
        let manager = try await loadManager()
        EventLog.shared.record(phase: "tunnel", kind: "startVPNTunnel",
                               detail: "status before start: \(Self.name(manager.connection.status))")
        try manager.connection.startVPNTunnel()
    }

    /// `NEVPNStatus` prints as a bare integer, which is useless in a log.
    static func name(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid:       return "invalid"
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting"
        case .connected:     return "connected"
        case .reasserting:   return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default:    return "unknown(\(status.rawValue))"
        }
    }

    /// `userInitiated: true` is an explicit "Disconnect"/"Cancel" from the UI.
    ///
    /// On-demand + a catch-all connect rule is the kill switch: while it is
    /// armed the OS restarts the extension the instant anything wants the
    /// network. That is correct for auto-connect, but it also means a plain
    /// `stopVPNTunnel()` is undone within a second — the user taps Cancel and
    /// the tunnel immediately comes back, connecting/disconnecting forever.
    /// An explicit disconnect therefore disarms on-demand first; the next
    /// explicit Connect (`install`) re-arms it. Nothing leaks in between
    /// because with the tunnel down and no rule, traffic simply uses the
    /// physical interface — which is what the user asked for by disconnecting.
    public func stop(userInitiated: Bool = false) async throws {
        let manager = try await loadManager()
        if userInitiated, manager.isOnDemandEnabled {
            EventLog.shared.record(phase: "profile", kind: "disarmingOnDemand",
                                   detail: "so the OS does not restart the tunnel we are stopping")
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            try? await manager.saveToPreferences()
            try? await manager.loadFromPreferences()
        }
        EventLog.shared.record(phase: "tunnel", level: .warn, kind: "stopVPNTunnel",
                               detail: "status: \(Self.name(manager.connection.status))")
        manager.connection.stopVPNTunnel()
    }

    /// Removing the profile also removes the kill switch — callers must warn.
    public func removeProfile() async throws {
        let manager = try await loadManager()
        try await manager.removeFromPreferences()
        withState {
            self.manager = nil
            ownsProfile = false
            // The cached load has to go too, or the next `loadManager()` hands
            // back the task that resolved to the profile we just removed.
            loadTask = nil
        }
    }

    public func send(_ message: AppToProvider) async throws -> ProviderToApp? {
        let manager = try await loadManager()
        guard let session = manager.connection as? NETunnelProviderSession else { return nil }
        let payload = try IPCCodec.encode(message)
        return try await withCheckedThrowingContinuation { cont in
            do {
                try session.sendProviderMessage(payload) { data in
                    guard let data else { return cont.resume(returning: nil) }
                    cont.resume(returning: try? IPCCodec.decode(ProviderToApp.self, data))
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    /// Whether *the saved profile* actually carries an on-demand rule. The UI must
    /// not show "Standing by" off a local toggle that was never written to a profile.
    public var profileOnDemandEnabled: Bool {
        withState {
            guard ownsProfile, let manager else { return false }
            return manager.isOnDemandEnabled && !(manager.onDemandRules ?? []).isEmpty
        }
    }

    /// `.invalid` unless the profile we are reading is provably ours.
    public var connectionStatus: NEVPNStatus {
        withState {
            guard ownsProfile, let manager else { return .invalid }
            return manager.connection.status
        }
    }
}

/// Rung 4: kernel IKEv2. It is a separate *profile* (NEVPNManager), not a
/// packet-tunnel adapter, which is exactly why it survives when the extension
/// cannot run and why it costs less battery.
public enum IKEv2Configurator {
    public static func install(server: Server, remoteIdentifier: String,
                               localIdentifier: String, policy: SecurityPolicy) async throws {
        let manager = NEVPNManager.shared()
        try await manager.loadFromPreferences()
        let proto = NEVPNProtocolIKEv2()
        guard let endpoint = server.endpoints.first(where: { $0.rung == .ikev2 }) else {
            throw AdapterFactoryError.noEndpoint(.ikev2)
        }
        proto.serverAddress = endpoint.host
        proto.remoteIdentifier = remoteIdentifier
        proto.localIdentifier = localIdentifier
        proto.authenticationMethod = .certificate      // EAP-TLS/cert, no shared secret
        proto.useExtendedAuthentication = false
        proto.disconnectOnSleep = false
        proto.enablePFS = true
        proto.useConfigurationAttributeInternalIPSubnet = false
        proto.includeAllNetworks = policy.includeAllNetworks
        proto.excludeLocalNetworks = policy.excludeLocalNetworks

        // Fixed, modern suites — no negotiation-down room.
        proto.ikeSecurityAssociationParameters.encryptionAlgorithm = .algorithmAES256GCM
        proto.ikeSecurityAssociationParameters.integrityAlgorithm = .SHA384
        proto.ikeSecurityAssociationParameters.diffieHellmanGroup = .group20
        proto.ikeSecurityAssociationParameters.lifetimeMinutes = 1440
        proto.childSecurityAssociationParameters.encryptionAlgorithm = .algorithmAES256GCM
        proto.childSecurityAssociationParameters.integrityAlgorithm = .SHA384
        proto.childSecurityAssociationParameters.diffieHellmanGroup = .group20
        proto.childSecurityAssociationParameters.lifetimeMinutes = 480

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Sweep VPN (IKEv2)"
        manager.isEnabled = true
        manager.isOnDemandEnabled = policy.onDemandEnabled
        manager.onDemandRules = policy.onDemandEnabled ? [NEOnDemandRuleConnect()] : []
        try await manager.saveToPreferences()
    }
}
