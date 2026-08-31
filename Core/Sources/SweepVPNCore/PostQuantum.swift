import Foundation
import CryptoKit

/// Hybrid post-quantum PSK for rungs 1–2 (Mullvad `wgephemeralpeer` model):
/// once the classical WireGuard tunnel is up, the client sends an ML-KEM-768
/// encapsulation key *inside* the tunnel, the server encapsulates, and the
/// resulting shared secret becomes the WireGuard preshared key for an
/// immediate rekey. No custom crypto: ML-KEM-768 (FIPS 203) + HKDF-SHA256,
/// both from CryptoKit, layered on unmodified WireGuard.
public enum PostQuantum {
    public enum Failure: Error, Equatable { case unsupportedOS, badCiphertext }

    /// True when this OS can do ML-KEM-768.
    public static var isAvailable: Bool {
        if #available(iOS 26.0, macOS 26.0, *) { return true }
        return false
    }

    @available(iOS 26.0, macOS 26.0, *)
    public struct Exchange {
        public let privateKey: MLKEM768.PrivateKey
        public init() throws { self.privateKey = try MLKEM768.PrivateKey() }
        /// Bytes to send to the server inside the established tunnel.
        public var encapsulationKey: Data { privateKey.publicKey.rawRepresentation }
        /// Derive the 32-byte WireGuard PSK from the server's ciphertext.
        public func psk(from ciphertext: Data) throws -> SymmetricKey {
            guard let secret = try? privateKey.decapsulate(ciphertext) else {
                throw Failure.badCiphertext
            }
            return HKDF<SHA256>.deriveKey(inputKeyMaterial: secret,
                                          info: Data("sweep-vpn/wg-psk/v1".utf8),
                                          outputByteCount: 32)
        }
    }
}
