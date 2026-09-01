import Foundation
import CryptoKit
import SweepVPNCore

/// Offline signing tool for the control plane.
///
///   sweep-sign keygen <private.key>            — generate the offline signing key
///   sweep-sign pubkey <private.key>            — print the base64 key to pin in the app
///   sweep-sign sign <private.key> <in.json> <out.sig.json>
///   sweep-sign verify <pub-b64> <out.sig.json>
///
/// The private key never touches the VPS: sign on an offline machine, publish
/// only the signed bundle to a static host.

func die(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    die("usage: sweep-sign keygen|pubkey|sign|verify …")
}

do {
switch command {
case "keygen":
    guard args.count == 2 else { die("usage: sweep-sign keygen <private.key>") }
    let key = Curve25519.Signing.PrivateKey()
    try key.rawRepresentation.write(to: URL(fileURLWithPath: args[1]), options: [.atomic])
    try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                           ofItemAtPath: args[1])
    print("public key (pin this in the app): \(key.publicKey.rawRepresentation.base64EncodedString())")

case "pubkey":
    guard args.count == 2 else { die("usage: sweep-sign pubkey <private.key>") }
    let raw = try Data(contentsOf: URL(fileURLWithPath: args[1]))
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    print(key.publicKey.rawRepresentation.base64EncodedString())

case "sign":
    guard args.count >= 4 else { die("usage: sweep-sign sign <private.key> <in.json> <out.sig.json> [--local-only]") }
    let key = try Curve25519.Signing.PrivateKey(
        rawRepresentation: try Data(contentsOf: URL(fileURLWithPath: args[1])))
    let bundle = try ConfigVerifier.decoder()
        .decode(ConfigBundle.self, from: try Data(contentsOf: URL(fileURLWithPath: args[2])))
    guard !bundle.servers.isEmpty else { die("refusing to sign a bundle with no servers") }
    // A bundle holding per-config device keys grants tunnel access to anyone who
    // downloads it. Signing one is fine for a build that embeds it in the app;
    // publishing it is not, so the intent has to be stated.
    let withKeys = bundle.servers.filter { $0.devicePrivateKey != nil }
    if !withKeys.isEmpty && !args.contains("--local-only") {
        die("""
            refusing to sign: \(withKeys.count) server(s) carry a device private key.
            Such a bundle must be embedded in the app, never hosted at SWEEP_CONFIG_URL.
            Re-run with --local-only if you are embedding it.
            """)
    }
    guard bundle.expiresAt > Date() else { die("refusing to sign an already-expired bundle") }
    let signed = try ConfigVerifier.sign(bundle, with: key)
    try IPCCodec.encode(signed).write(to: URL(fileURLWithPath: args[3]), options: [.atomic])
    print("signed version \(bundle.version), \(bundle.servers.count) server(s), expires \(bundle.expiresAt)")

case "verify":
    guard args.count == 3 else { die("usage: sweep-sign verify <pub-b64> <out.sig.json>") }
    guard let raw = Data(base64Encoded: args[1]), raw.count == 32 else { die("bad public key") }
    let pub = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    let signed = try IPCCodec.decode(SignedBundle.self,
                                     try Data(contentsOf: URL(fileURLWithPath: args[2])))
    let bundle = try ConfigVerifier.verify(signed, pinnedKey: pub, currentVersion: nil,
                                           appBuild: .max, now: Date())
    print("ok: version \(bundle.version), expires \(bundle.expiresAt), servers \(bundle.servers.map(\.name))")

default:
    die("unknown command \(command)")
}
} catch {
    die("error: \(error)")
}
