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

    public init(bundleIdentifier: String, displayName: String = "Sweep VPN") {
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
    }

    public func loadManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        let existing = try await NETunnelProviderManager.loadAllFromPreferences()
        let m = existing.first ?? NETunnelProviderManager()
        manager = m
        return m
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

    public var connectionStatus: NEVPNStatus {
        manager?.connection.status ?? .invalid
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
