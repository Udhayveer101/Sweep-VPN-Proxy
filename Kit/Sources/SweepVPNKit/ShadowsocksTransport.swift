import Foundation
import Network
import SweepVPNCore
import SweepWireGuardC

/// Rung 5: WireGuard inside a Shadowsocks-2022 (AEAD, BLAKE3) connection.
/// The upstream shadowsocks client runs in the Rust core and exposes a loopback
/// TCP endpoint; from Swift's point of view this is an ordinary stream transport
/// whose bytes happen to leave the device as SS2022. The server is a stock
/// `ssserver` — no bespoke server component, and no crypto written by us.
public final class ShadowsocksTransport: PacketTransport, @unchecked Sendable {
    public let rung: ProtocolRung = .shadowsocks2022

    private let serverHost: String
    private let serverPort: UInt16
    private let key: Data
    private var handle: OpaquePointer?
    private var inner: StreamTransport?

    init(host: NWEndpoint.Host, port: NWEndpoint.Port, key: Data) {
        self.serverHost = "\(host)"
        self.serverPort = port.rawValue
        self.key = key
    }

    public func start(onReady: @escaping @Sendable () -> Void,
                      onDatagram: @escaping @Sendable (Data) -> Void,
                      onFailure: @escaping @Sendable () -> Void) {
        var out: OpaquePointer?
        let password = key.base64EncodedString()
        // The tunnel's far end is the WireGuard port on the same VPS.
        let localPort = serverHost.withCString { sh in
            password.withCString { pw in
                "127.0.0.1".withCString { th in
                    sweepss_start(sh, serverPort, pw, th, 51820, &out)
                }
            }
        }
        guard localPort > 0, let out, let nwPort = NWEndpoint.Port(rawValue: localPort) else {
            return onFailure()
        }
        handle = out
        let stream = StreamTransport(rung: rung, host: "127.0.0.1", port: nwPort, parameters: .tcp)
        inner = stream
        stream.start(onReady: onReady, onDatagram: onDatagram, onFailure: onFailure)
    }

    public func send(_ datagram: Data) { inner?.send(datagram) }

    public func stop() {
        inner?.stop()
        inner = nil
        if let handle { sweepss_stop(handle) }
        handle = nil
    }
}
