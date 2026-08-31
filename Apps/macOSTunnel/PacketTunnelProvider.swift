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

    override var appBuild: Int { AppConfig.appBuild }
}
