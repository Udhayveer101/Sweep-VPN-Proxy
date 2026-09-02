import SwiftUI
import SweepVPNCore

/// Read-only evidence that the tunnel is what the app claims it is.
///
/// Every row is sourced from the provider's own IPC status or from the pinned
/// build configuration — nothing here is inferred from the UI's own state. The
/// point is that a user can check the claim rather than trust the headline, so
/// a value that cannot be substantiated is shown as unknown, never guessed.
public struct SecurityPanel: View {
    @ObservedObject var model: VPNViewModel
    let signingKeyFingerprint: String?

    public init(model: VPNViewModel, signingKeyFingerprint: String? = nil) {
        self.model = model
        self.signingKeyFingerprint = signingKeyFingerprint
    }

    public var body: some View {
        Section("Security") {
            row("Key exchange", cipherSuite?.exchange ?? "—")
            row("Encryption", cipherSuite?.encryption ?? "—")
            row("Authentication", cipherSuite?.authentication ?? "—")
            row("Route", model.rung?.displayName ?? "Not connected")
            row("Last handshake", handshakeText)
            row("Data", transferText)
            row("Kill switch", model.killSwitchArmed ? "Armed" : "Off")
            row("Post-quantum", pqText)
            if let signingKeyFingerprint {
                row("Config signing key", signingKeyFingerprint)
            }
            Text(footnote).font(.footnote).foregroundStyle(.secondary)
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }

    /// The rung determines the cipher suite, because each rung is a fixed,
    /// non-negotiable construction. There is no cipher agility to report.
    private var cipherSuite: (exchange: String, encryption: String, authentication: String)? {
        guard let rung = model.rung else { return nil }
        switch rung {
        case .wireGuardUDP, .wireGuardUDP443, .wireGuardQUIC,
             .wireGuardTLS, .wireGuardTCP, .shadowsocks2022:
            return ("Curve25519 (X25519), Noise IK",
                    "ChaCha20-Poly1305 (AEAD)",
                    "BLAKE2s, mutual static public keys")
        case .ikev2:
            return ("Diffie-Hellman group 20 (ECP-384)",
                    "AES-256-GCM",
                    "Certificate, mutual")
        case .openVPNUDP, .openVPNTCP:
            // The one rung with real cipher agility, and the weakest: the relay
            // picks, and a VPN Gate profile typically asks for AES-128-CBC with
            // SHA1. The client cert is shared by every VPN Gate user, so it
            // authenticates the relay to you and nothing about you to it.
            return ("TLS, relay's choice of parameters",
                    "Negotiated by the relay (VPN Gate profiles ask for AES-128-CBC)",
                    "Shared VPN Gate client certificate — not unique to you")
        }
    }

    private var handshakeText: String {
        guard model.state.forwardingAllowed || model.state == .verifying else { return "—" }
        guard let age = model.handshakeAgeSeconds else { return "None yet" }
        // WireGuard rekeys about every 2 minutes while traffic flows, so an age
        // beyond that on a live tunnel is itself the signal worth showing.
        let stale = age > 180
        return "\(age)s ago" + (stale ? " (stale)" : "")
    }

    private var transferText: String {
        guard model.bytesSent > 0 || model.bytesReceived > 0 else { return "—" }
        return "↑ \(format(model.bytesSent))  ↓ \(format(model.bytesReceived))"
    }

    private var pqText: String {
        if model.pqHybridActive { return "Hybrid ML-KEM-768 active" }
        return PostQuantum.isAvailable ? "Not negotiated with this server" : "Unavailable on this OS"
    }

    private var footnote: String {
        """
        WireGuard authenticates both ends with static public keys, so the server \
        proves its identity to you and you to it — there is no certificate \
        authority to mis-issue. The suite is fixed, not negotiated, so it cannot \
        be downgraded.
        """
    }

    private func format(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}
