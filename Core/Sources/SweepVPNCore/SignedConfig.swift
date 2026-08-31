import Foundation
import CryptoKit

/// The config + server list delivered by the control plane. It is signed
/// offline with Ed25519; the public key is pinned in the app binary.
/// Every failure mode here is fail-closed (vault 05-Security/Anti-Downgrade-Signed-Config).
public struct ConfigBundle: Codable, Sendable, Equatable {
    public var version: UInt64          // monotonic — never accept a lower one
    public var issuedAt: Date
    public var expiresAt: Date
    public var minimumAppBuild: Int     // downgrade resistance for the client itself
    public var servers: [Server]
    public var enabledRungs: [ProtocolRung]

    public init(version: UInt64, issuedAt: Date, expiresAt: Date, minimumAppBuild: Int,
                servers: [Server], enabledRungs: [ProtocolRung]) {
        self.version = version; self.issuedAt = issuedAt; self.expiresAt = expiresAt
        self.minimumAppBuild = minimumAppBuild; self.servers = servers
        self.enabledRungs = enabledRungs
    }
}

/// Wire format: {"payload": <base64 canonical JSON>, "signature": <base64 Ed25519>}
public struct SignedBundle: Codable, Sendable, Equatable {
    public var payload: Data
    public var signature: Data
    public init(payload: Data, signature: Data) { self.payload = payload; self.signature = signature }
}

public enum ConfigError: Error, Equatable {
    case badSignature
    case malformed
    case rollback(have: UInt64, offered: UInt64)
    case expired(at: Date)
    case notYetValid(at: Date)
    case appTooOld(required: Int, have: Int)
    case noServers
}

public enum ConfigVerifier {
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]   // canonical
        e.dateEncodingStrategy = .secondsSince1970
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }

    /// Verify signature, freshness, monotonicity and client-version floor.
    /// Any failure leaves the caller on the last-known-good bundle (or offline).
    public static func verify(_ signed: SignedBundle,
                              pinnedKey: Curve25519.Signing.PublicKey,
                              currentVersion: UInt64?,
                              appBuild: Int,
                              now: Date,
                              clockSkew: TimeInterval = 300) throws -> ConfigBundle {
        guard pinnedKey.isValidSignature(signed.signature, for: signed.payload) else {
            throw ConfigError.badSignature
        }
        guard let bundle = try? decoder().decode(ConfigBundle.self, from: signed.payload) else {
            throw ConfigError.malformed
        }
        if let current = currentVersion, bundle.version < current {
            throw ConfigError.rollback(have: current, offered: bundle.version)
        }
        if now > bundle.expiresAt.addingTimeInterval(clockSkew) {
            throw ConfigError.expired(at: bundle.expiresAt)
        }
        if now < bundle.issuedAt.addingTimeInterval(-clockSkew) {
            throw ConfigError.notYetValid(at: bundle.issuedAt)
        }
        guard appBuild >= bundle.minimumAppBuild else {
            throw ConfigError.appTooOld(required: bundle.minimumAppBuild, have: appBuild)
        }
        guard !bundle.servers.isEmpty else { throw ConfigError.noServers }
        return bundle
    }

    /// Used by the offline signing tool and by tests.
    public static func sign(_ bundle: ConfigBundle,
                            with key: Curve25519.Signing.PrivateKey) throws -> SignedBundle {
        let payload = try encoder().encode(bundle)
        return SignedBundle(payload: payload, signature: try key.signature(for: payload))
    }
}
