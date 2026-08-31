import Foundation

/// Platform-neutral description of the tunnel settings. The provider maps this
/// onto NEPacketTunnelNetworkSettings; keeping it as plain data makes the
/// leak-critical decisions testable on the host.
public struct TunnelPlan: Sendable, Equatable {
    public struct Route: Sendable, Equatable {
        public var address: String
        public var prefix: Int
        public init(_ address: String, _ prefix: Int) { self.address = address; self.prefix = prefix }
    }
    public var tunnelRemoteAddress: String
    public var ipv4Address: String
    public var ipv4Routes: [Route]
    public var ipv4ExcludedRoutes: [Route]
    public var ipv6Address: String?
    public var ipv6Routes: [Route]
    public var ipv6Blocked: Bool          // no v6 address -> v6 must be blackholed, never left to wifi
    public var dnsServers: [String]
    public var dnsMatchDomains: [String]  // [""] = all queries in tunnel
    public var splitDNSDomains: [String]  // LAN suffixes resolved outside
    public var mtu: Int
    /// Blackhole state: forwarding is refused until the peer is authenticated.
    public var forwardingEnabled: Bool
}

public struct SecurityPolicyOptions: Sendable, Equatable, Codable {
    public var killSwitchEnabled: Bool = true
    public var excludeLocalNetworks: Bool = true      // LAN reachable; documented trade-off
    public var blockIPv6WhenUnavailable: Bool = true
    public var allowCaptivePortalWindow: Bool = false // opt-in, time-boxed
    public var lanSuffixes: [String] = ["local"]
    public init() {}
}

/// The single chokepoint for "may cleartext leave this device?".
/// No other module is allowed to answer that question.
public struct SecurityPolicy: Sendable {
    public var options: SecurityPolicyOptions
    public init(options: SecurityPolicyOptions = .init()) { self.options = options }

    /// Settings applied *before* the handshake completes: full default route,
    /// forwarding off. This is the blackhole that makes failure fail-closed.
    public func blackholePlan(mtu: Int = 1280) -> TunnelPlan {
        TunnelPlan(tunnelRemoteAddress: "127.0.0.1",
                   ipv4Address: "169.254.0.1",
                   ipv4Routes: [.init("0.0.0.0", 0)],
                   ipv4ExcludedRoutes: [],
                   ipv6Address: nil,
                   ipv6Routes: [.init("::", 0)],
                   ipv6Blocked: true,
                   dnsServers: ["127.0.0.1"],
                   dnsMatchDomains: [""],
                   splitDNSDomains: [],
                   mtu: mtu,
                   forwardingEnabled: false)
    }

    /// Settings applied once the peer is authenticated and a packet has round-tripped.
    public func connectedPlan(server: Server, endpoint: ServerEndpoint, mtu: Int = 1280) -> TunnelPlan {
        let hasV6 = server.ipv6Address != nil
        return TunnelPlan(
            tunnelRemoteAddress: endpoint.host,
            ipv4Address: server.ipv4Address,
            ipv4Routes: [.init("0.0.0.0", 0)],
            ipv4ExcludedRoutes: [],
            ipv6Address: server.ipv6Address,
            // Either route v6 into the tunnel, or blackhole it. Never leave it
            // to the physical interface (vault 01-Apple-Platform/IPv4-IPv6-Routing-And-Leak-Risk).
            ipv6Routes: (hasV6 || options.blockIPv6WhenUnavailable) ? [.init("::", 0)] : [],
            ipv6Blocked: !hasV6 && options.blockIPv6WhenUnavailable,
            dnsServers: server.dnsServers,
            dnsMatchDomains: [""],
            splitDNSDomains: options.lanSuffixes,
            mtu: mtu,
            forwardingEnabled: true)
    }

    /// Whether a packet read from the tunnel interface may be forwarded.
    public func mayForward(state: TunnelState) -> Bool { state.forwardingAllowed }

    /// Whether the OS-level kill switch flags should be set on the VPN profile.
    public var includeAllNetworks: Bool { options.killSwitchEnabled }
    public var excludeLocalNetworks: Bool { options.excludeLocalNetworks }

    /// On-demand catch-all is our App-Store-legal stand-in for always-on.
    public var onDemandEnabled: Bool { options.killSwitchEnabled }
}
