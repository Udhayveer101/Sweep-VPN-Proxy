import Foundation

/// Network settings a peer assigns at connect time.
///
/// The WireGuard rungs never need this: the tunnel address, resolvers and
/// routes all come out of the signature-verified bundle before a single packet
/// moves, which is part of why that path can be checked offline. OpenVPN is the
/// opposite — the relay decides in its PUSH_REPLY, so none of it is known until
/// the session is already up.
///
/// That is a real difference in what can be trusted, not a formatting detail:
/// everything here is remote input from a machine we do not run, so it is
/// validated before it is turned into tunnel settings rather than after.
public struct PushedTunnelSettings: Codable, Sendable, Equatable {
    public struct Address: Codable, Sendable, Equatable {
        public var address: String
        public var prefix: Int
        public var gateway: String
        public var ipv6: Bool
    }

    public struct Route: Codable, Sendable, Equatable {
        public var address: String
        public var prefix: Int
        public var ipv6: Bool
        public var exclude: Bool
    }

    public var mtu: Int
    public var remote: String
    public var sessionName: String
    public var redirectGatewayV4: Bool
    public var redirectGatewayV6: Bool
    public var addresses: [Address]
    public var routes: [Route]
    public var dns: [String]

    public init(mtu: Int = 0, remote: String = "", sessionName: String = "",
                redirectGatewayV4: Bool = false, redirectGatewayV6: Bool = false,
                addresses: [Address] = [], routes: [Route] = [], dns: [String] = []) {
        self.mtu = mtu
        self.remote = remote
        self.sessionName = sessionName
        self.redirectGatewayV4 = redirectGatewayV4
        self.redirectGatewayV6 = redirectGatewayV6
        self.addresses = addresses
        self.routes = routes
        self.dns = dns
    }

    /// A relay that pushed no usable address gave us nothing to build a tunnel
    /// from, whatever else it said.
    public var hasUsableAddress: Bool { ipv4Address != nil }

    public var ipv4Address: Address? { addresses.first { !$0.ipv6 } }
    public var ipv6Address: Address? { addresses.first { $0.ipv6 } }

    /// MTU to install, clamped to something a tunnel can actually carry. A
    /// relay that pushes 0 (VPN Gate does) or something absurd must not be
    /// allowed to produce an unusable interface.
    ///
    /// The fallback is 1280, not 1400, because of what the packet is wrapped in
    /// on the rungs that need this: inner IP inside OpenVPN inside a WebSocket
    /// frame inside TLS inside the outer TCP/IP, which is 110-140 bytes of
    /// headers before anything of ours is on the wire. At 1400 every full-size
    /// packet fragments at the outer layer, and on a TCP-over-TCP path a lost
    /// fragment costs far more than the payload it carried. 1280 is also the
    /// IPv6 minimum, so nothing downstream has to special-case it.
    public var effectiveMTU: Int {
        (576...1500).contains(mtu) ? mtu : 1280
    }

    // MARK: - Validation

    public enum Rejection: Error, Equatable, CustomStringConvertible {
        case noAddress
        case malformedAddress(String)
        case badPrefix(String, Int)

        public var description: String {
            switch self {
            case .noAddress:
                return "the relay pushed no tunnel address"
            case .malformedAddress(let a):
                return "the relay pushed a malformed address (\(a))"
            case .badPrefix(let a, let p):
                return "the relay pushed an out-of-range prefix (\(a)/\(p))"
            }
        }
    }

    /// Reject anything we would not want to hand to the OS.
    ///
    /// The dangerous field is DNS: a relay that pushes a resolver is choosing
    /// who answers every name the device looks up. We cannot stop it doing that
    /// — it is how OpenVPN works, and the operator sees the traffic regardless
    /// — but a malformed entry must not reach the network settings, and the
    /// user is told which resolver is in force.
    public func validated() throws -> PushedTunnelSettings {
        guard let v4 = ipv4Address else { throw Rejection.noAddress }
        guard Self.isIPv4(v4.address) else { throw Rejection.malformedAddress(v4.address) }
        guard (0...32).contains(v4.prefix) else {
            throw Rejection.badPrefix(v4.address, v4.prefix)
        }

        var copy = self
        copy.addresses = addresses.filter {
            $0.ipv6 ? Self.isIPv6($0.address) : Self.isIPv4($0.address)
        }
        copy.routes = routes.filter {
            ($0.ipv6 ? Self.isIPv6($0.address) : Self.isIPv4($0.address))
                && (0...($0.ipv6 ? 128 : 32)).contains($0.prefix)
        }
        copy.dns = dns.filter { Self.isIPv4($0) || Self.isIPv6($0) }
        copy.mtu = effectiveMTU
        return copy
    }

    static func isIPv4(_ s: String) -> Bool {
        var addr = in_addr()
        return !s.isEmpty && s.withCString { inet_pton(AF_INET, $0, &addr) == 1 }
    }

    static func isIPv6(_ s: String) -> Bool {
        var addr = in6_addr()
        return !s.isEmpty && s.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }
}
