import Foundation
import CryptoKit
import SweepVPNCore

/// Build-time constants. The config-signing public key is *pinned here*: the
/// control plane has no way to introduce a new key at runtime, so a compromised
/// distribution host cannot hand out a valid-looking server list.
public enum AppConfig {
    public static let appGroup = "group.com.sweep.vpn"
    public static let keychainService = "com.sweep.vpn"
    #if os(iOS)
    public static let tunnelBundleID = "com.sweep.vpn.ios.tunnel"
    #else
    public static let tunnelBundleID = "com.sweep.vpn.mac.tunnel"
    #endif

    /// Ed25519 public key, base64, injected at build time from
    /// SWEEP_CONFIG_SIGNING_KEY. Empty means "no pinned key", which makes
    /// `pinnedSigningKey()` throw and the app refuse to connect.
    public static let configSigningPublicKeyBase64 =
        (Bundle.main.object(forInfoDictionaryKey: "SweepConfigSigningKey") as? String) ?? ""

    /// Static host serving the offline-signed bundle. No account API.
    public static var configURL: URL? {
        (Bundle.main.object(forInfoDictionaryKey: "SweepConfigURL") as? String)
            .flatMap(URL.init(string:))
    }

    /// Worker that carries a relay's TCP stream inside WSS. Injected at build
    /// time so the token is not a literal in the source tree.
    public static var tunnelURL: URL? {
        (Bundle.main.object(forInfoDictionaryKey: "SweepTunnelURL") as? String)
            .flatMap(URL.init(string:))
    }

    public static var tunnelToken: String {
        (Bundle.main.object(forInfoDictionaryKey: "SweepTunnelToken") as? String) ?? ""
    }

    public static var appBuild: Int {
        Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1") ?? 1
    }

    public static func pinnedSigningKey() throws -> Curve25519.Signing.PublicKey {
        guard let raw = Data(base64Encoded: configSigningPublicKeyBase64), raw.count == 32 else {
            throw ConfigError.badSignature      // fail closed: no key, no config, no tunnel
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }

    /// The app and the extension share secrets through the App Group keychain.
    /// On the simulator that entitlement is not granted (and a simulator cannot
    /// host a NetworkExtension at all, so nothing is shared there) — fall back to
    /// the app's own keychain so the UI can still be exercised.
    public static var keychainAccessGroup: String? {
        #if targetEnvironment(simulator)
        return nil
        #else
        return appGroup
        #endif
    }

    public static func makeConfigStore() throws -> ConfigStore {
        ConfigStore(store: KeychainStore(service: keychainService, accessGroup: keychainAccessGroup),
                    pinnedSigningKey: try pinnedSigningKey(),
                    appBuild: appBuild)
    }
}
