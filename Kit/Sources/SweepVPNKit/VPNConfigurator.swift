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
    public func loadManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        let existing = try await NETunnelProviderManager.loadAllFromPreferences()
        let ours = Self.selectOurs(from: existing, bundleIdentifier: bundleIdentifier)
        let m = ours ?? NETunnelProviderManager()
        ownsProfile = (ours != nil)
        manager = m
        return m
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
    public var hasInstalledProfile: Bool { ownsProfile }

    /// The connection object for *our* profile, for scoping `NEVPNStatusDidChange`
    /// observation. Observing with `object: nil` delivers every VPN's transitions.
    public var ourConnection: NEVPNConnection? {
        ownsProfile ? manager?.connection : nil
    }

    /// Applies the researched kill-switch construction:
    /// on-demand catch-all + includeAllNetworks + excludeLocalNetworks.
    public func install(policy: SecurityPolicy, serverDescription: String) async throws {
        let manager = try await loadManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = bundleIdentifier
        proto.serverAddress = serverDescription
        proto.includeAllNetworks = policy.includeAllNetworks
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

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        ownsProfile = true
    }

    public func start() async throws {
        let manager = try await loadManager()
        try manager.connection.startVPNTunnel()
    }

    public func stop() async throws {
        let manager = try await loadManager()
        manager.connection.stopVPNTunnel()
    }

    /// Removing the profile also removes the kill switch — callers must warn.
    public func removeProfile() async throws {
        let manager = try await loadManager()
        try await manager.removeFromPreferences()
        self.manager = nil
        ownsProfile = false
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
        guard ownsProfile, let manager else { return false }
        return manager.isOnDemandEnabled && !(manager.onDemandRules ?? []).isEmpty
    }

    /// `.invalid` unless the profile we are reading is provably ours.
    public var connectionStatus: NEVPNStatus {
        guard ownsProfile, let manager else { return .invalid }
        return manager.connection.status
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
