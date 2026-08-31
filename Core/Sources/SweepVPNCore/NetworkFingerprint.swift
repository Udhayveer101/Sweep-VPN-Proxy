import Foundation
import CryptoKit

/// Per-network memory must not be keyed by anything that could identify the
/// network if the device is seized or the store leaks — so the key is
/// HMAC(deviceSecret, SSID‖gatewayMAC‖DNSsuffix‖interface).
public enum NetworkFingerprint {
    public static func key(deviceSecret: SymmetricKey,
                           ssid: String?,
                           gatewayMAC: String?,
                           dnsSuffix: String?,
                           interface: String) -> String {
        let material = [ssid ?? "", gatewayMAC ?? "", dnsSuffix ?? "", interface]
            .joined(separator: "\u{1F}")
        let mac = HMAC<SHA256>.authenticationCode(for: Data(material.utf8), using: deviceSecret)
        return Data(mac).prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
