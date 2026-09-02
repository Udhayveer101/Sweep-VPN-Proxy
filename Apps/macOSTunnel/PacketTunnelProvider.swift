import Foundation
import NetworkExtension
import SweepVPNCore
import SweepVPNKit

/// Platform packaging only — all behaviour lives in SweepPacketTunnelProvider so
/// iOS and macOS cannot drift apart on anything security-relevant.
final class PacketTunnelProvider: SweepPacketTunnelProvider {
    /// If the keychain or the pinned signing key is unavailable this returns nil
    /// and the tunnel refuses to start, leaving the blackhole in place.
    override var configStore: ConfigStore? { try? AppConfig.makeConfigStore() }

    /// macOS runs a second, independent kill-switch layer; the tunnel tells it
    /// when traffic may leave.
    override var filterStateStore: FilterStateStore? {
        FilterStateStore(appGroup: AppConfig.appGroup)
    }

    override var appBuild: Int { AppConfig.appBuild }

    /// Shared with the app so the failed-start streak survives this process
    /// being torn down and restarted by on-demand.
    override var backoffStore: StartBackoffStore? {
        StartBackoffStore(appGroup: AppConfig.appGroup)
    }

    /// macOS is the only platform where the OpenVPN rungs are built, so it is
    /// the only one that can act on a chosen public relay.
    override var relayStore: RelaySelectionStore? {
        RelaySelectionStore(appGroup: AppConfig.appGroup)
    }
}
