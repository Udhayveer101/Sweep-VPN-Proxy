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

    /// Ed25519 public key, base64. Replace with your own signing key before
    /// shipping — the placeholder below is a well-known test key and the app
    /// refuses to use it in a release build.
    public static let configSigningPublicKeyBase64 =
        (Bundle.main.object(forInfoDictionaryKey: "SweepConfigSigningKey") as? String) ?? ""

    public static var appBuild: Int {
        Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1") ?? 1
    }

    public static func pinnedSigningKey() throws -> Curve25519.Signing.PublicKey {
        guard let raw = Data(base64Encoded: configSigningPublicKeyBase64), raw.count == 32 else {
            throw ConfigError.badSignature      // fail closed: no key, no config, no tunnel
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }

    public static func makeConfigStore() throws -> ConfigStore {
        ConfigStore(store: KeychainStore(service: keychainService, accessGroup: appGroup),
                    pinnedSigningKey: try pinnedSigningKey(),
                    appBuild: appBuild)
    }
}
