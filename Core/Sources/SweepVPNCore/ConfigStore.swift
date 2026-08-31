import Foundation
import CryptoKit

/// Everything secret goes here. Never UserDefaults, never a plist, never a file.
public protocol SecretStore: Sendable {
    func set(_ data: Data, for key: String) throws
    func get(_ key: String) throws -> Data?
    func remove(_ key: String) throws
}

public enum SecretStoreError: Error, Equatable { case keychain(OSStatus) }

/// App-Group Keychain store, AfterFirstUnlock + ThisDeviceOnly so the extension
/// can read it on a locked device but nothing syncs or restores to another device.
public struct KeychainStore: SecretStore {
    public let service: String
    public let accessGroup: String?

    public init(service: String = "com.sweep.vpn", accessGroup: String? = nil) {
        self.service = service; self.accessGroup = accessGroup
    }

    private func query(_ key: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: key]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func set(_ data: Data, for key: String) throws {
        var attrs = query(key)
        SecItemDelete(attrs as CFDictionary)
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw SecretStoreError.keychain(status) }
    }

    public func get(_ key: String) throws -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw SecretStoreError.keychain(status) }
        return out as? Data
    }

    public func remove(_ key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStoreError.keychain(status)
        }
    }
}

/// In-memory store for host tests and previews.
public final class MemoryStore: SecretStore, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()
    public init() {}
    public func set(_ data: Data, for key: String) throws {
        lock.lock(); items[key] = data; lock.unlock()
    }
    public func get(_ key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }; return items[key]
    }
    public func remove(_ key: String) throws { lock.lock(); items[key] = nil; lock.unlock() }
}

/// Device identity + the last-known-good signed bundle.
public struct ConfigStore: Sendable {
    private enum Key {
        static let devicePrivateKey = "device.wg.private"
        static let deviceSecret = "device.fingerprint.secret"
        static let bundle = "config.bundle.signed"
        static let bundleVersion = "config.bundle.version"
    }

    public let store: SecretStore
    public let pinnedSigningKey: Curve25519.Signing.PublicKey
    public let appBuild: Int

    public init(store: SecretStore, pinnedSigningKey: Curve25519.Signing.PublicKey, appBuild: Int) {
        self.store = store; self.pinnedSigningKey = pinnedSigningKey; self.appBuild = appBuild
    }

    public func devicePrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let raw = try store.get(Key.devicePrivateKey) {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        try store.set(key.rawRepresentation, for: Key.devicePrivateKey)
        return key
    }

    public func fingerprintSecret() throws -> SymmetricKey {
        if let raw = try store.get(Key.deviceSecret) { return SymmetricKey(data: raw) }
        let key = SymmetricKey(size: .bits256)
        try store.set(key.withUnsafeBytes { Data($0) }, for: Key.deviceSecret)
        return key
    }

    public var currentVersion: UInt64? {
        guard let d = try? store.get(Key.bundleVersion), d.count == 8 else { return nil }
        return d.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
    }

    /// Accepts a candidate bundle only if it verifies; otherwise the old one stands.
    @discardableResult
    public func accept(_ signed: SignedBundle, now: Date = Date()) throws -> ConfigBundle {
        let bundle = try ConfigVerifier.verify(signed, pinnedKey: pinnedSigningKey,
                                               currentVersion: currentVersion,
                                               appBuild: appBuild, now: now)
        try store.set(IPCCodec.encode(signed), for: Key.bundle)
        var v = bundle.version
        try store.set(Data(bytes: &v, count: 8), for: Key.bundleVersion)
        return bundle
    }

    /// Last-known-good bundle, re-verified on every read (fail-closed on tamper).
    public func loadBundle(now: Date = Date()) throws -> ConfigBundle? {
        guard let data = try store.get(Key.bundle) else { return nil }
        let signed = try IPCCodec.decode(SignedBundle.self, data)
        return try ConfigVerifier.verify(signed, pinnedKey: pinnedSigningKey,
                                         currentVersion: nil, appBuild: appBuild, now: now)
    }
}
