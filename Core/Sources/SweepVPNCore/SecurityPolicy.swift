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
    /// Addresses that must stay on the physical interface while the v6 default
    /// route is ours. Without this the blackhole swallowed the Worker leg: the
    /// name resolves to A *and* AAAA records, the system prefers v6, the SYN
    /// went into `::/0` and was dropped, and `NWConnection` sat in `.preparing`
    /// — no `.ready`, no `.failed`, no `.waiting`, nothing logged at all until
    /// OpenVPN's own ten-second retry. A v4-only exclusion list is only correct
    /// on a v4-only network.
    public var ipv6ExcludedRoutes: [Route]
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
    /// Opt-in ad/tracker/malware blocking done by the in-tunnel resolver
    /// (Proton-NetShield / Mullvad-DNS class, vault What-Leading-VPNs-Do-Best).
    /// It selects a different resolver address on the same VPS — no third party.
    public var dnsFilteringEnabled: Bool = false

    /// Route app traffic through Tor *on top of* the tunnel. Tor runs in the app,
    /// not the extension, so its circuits are built through the VPN — which is
    /// Bridge lines from https://bridges.torproject.org. Only needed when the
    /// network blocks Tor and the VPN is not carrying it; empty means direct.
    public var torBridges: [String] = []
    /// Cloudflare WARP over MASQUE (usque) as the local proxy's upstream. App-
    /// side only, like Tor, and mutually exclusive with it.
    public var warpEnabled: Bool = false
    /// SNI presented to Cloudflare. Any neutral name works; the gateway resets
    /// the real consumer-masque.cloudflareclient.com.
    public var warpSNI: String = "example.com"
    public var warpSocksPort: Int = 1081
    /// Local SOCKS5 / HTTP-CONNECT listener for apps that should use the tunnel
    /// (or Tor) without the whole system being routed through it.
    public var localProxyEnabled: Bool = false
    public var localProxyPort: Int = 1080
    /// Send proxied connections to the Worker rather than straight out. On a
    /// filtered network "straight out" is the thing that does not work.
    public var proxyThroughWorker: Bool = false

    /// Domains the macOS content filter drops outright. Unlike DNS-based
    /// blocking this applies to the connection itself, so it holds *even when
    /// the tunnel is off* — the "non-VPN protection" case. Matching is by
    /// suffix, so "ads.example.com" blocks "x.ads.example.com" too.
    public var blockedDomains: [String] = []

    public init() {}
}

/// The single chokepoint for "may cleartext leave this device?".
/// No other module is allowed to answer that question.
public struct SecurityPolicy: Sendable {
    public var options: SecurityPolicyOptions
    public init(options: SecurityPolicyOptions = .init()) { self.options = options }

    /// Settings applied *before* the handshake completes: full default route,
    /// forwarding off. This is the blackhole that makes failure fail-closed.
    ///
    /// `reachableHosts` are the addresses the tunnel needs in order to build
    /// itself — today the Cloudflare Worker that carries the relay's stream.
    /// The blackhole is installed before the connection is dialled, so without
    /// excluding them the tunnel routes its own uplink into the dead interface
    /// it is still constructing and the transport dies instantly with
    /// NETWORK_RECV_ERROR. Excluding a host it is already about to talk to
    /// gives away nothing: traffic to it is what the blackhole exists to permit.
    public func blackholePlan(mtu: Int = 1280,
                              reachableHosts: Set<String> = []) -> TunnelPlan {
        TunnelPlan(tunnelRemoteAddress: "127.0.0.1",
                   ipv4Address: "169.254.0.1",
                   ipv4Routes: [.init("0.0.0.0", 0)],
                   ipv4ExcludedRoutes: reachableHosts
                       .filter { !$0.contains(":") }
                       .sorted()
                       .map { .init($0, 32) },
                   ipv6Address: nil,
                   ipv6Routes: [.init("::", 0)],
                   ipv6ExcludedRoutes: reachableHosts
                       .filter { $0.contains(":") }
                       .sorted()
                       .map { .init($0, 128) },
                   ipv6Blocked: true,
                   // DNS is deliberately NOT captured here. The blackhole is
                   // installed before the Worker is dialled, and the transport
                   // dials it by hostname, so pointing every domain at a
                   // resolver that does not exist made the tunnel unable to
                   // resolve the one name it needs to come up.
                   //
                   // Accepted trade-off: for the seconds between the blackhole
                   // going up and the peer authenticating, DNS queries leave in
                   // plaintext on the physical interface. Traffic still cannot:
                   // the default route is ours and forwarding is off. Once
                   // `connectedPlan` replaces this, all DNS is in-tunnel again.
                   dnsServers: [],
                   dnsMatchDomains: [],
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
            ipv6ExcludedRoutes: [],
            ipv6Blocked: !hasV6 && options.blockIPv6WhenUnavailable,
            dnsServers: options.dnsFilteringEnabled && !server.filteringDNSServers.isEmpty
                ? server.filteringDNSServers : server.dnsServers,
            dnsMatchDomains: [""],
            splitDNSDomains: options.lanSuffixes,
            mtu: mtu,
            forwardingEnabled: true)
    }

    /// The same plan, built from what an OpenVPN relay pushed rather than from
    /// the `Server` record — which for a public relay carries no address at all,
    /// because none exists until PUSH_REPLY.
    ///
    /// The IPv6 rule is unchanged and matters more here, not less: VPN Gate
    /// relays are IPv4-only, so without blackholing v6 every AAAA-reachable site
    /// would quietly bypass the tunnel over the physical interface.
    public func connectedPlan(server: Server,
                              endpoint: ServerEndpoint,
                              pushed: PushedTunnelSettings) -> TunnelPlan {
        let v4 = pushed.ipv4Address
        let v6 = pushed.ipv6Address
        let hasV6 = v6 != nil

        let pushedRoutes = pushed.routes.filter { !$0.exclude && !$0.ipv6 }
            .map { TunnelPlan.Route($0.address, $0.prefix) }
        let excluded = pushed.routes.filter { $0.exclude && !$0.ipv6 }
            .map { TunnelPlan.Route($0.address, $0.prefix) }

        return TunnelPlan(
            tunnelRemoteAddress: endpoint.host,
            ipv4Address: v4?.address ?? "",
            // redirect-gateway means the relay wants everything; otherwise honour
            // exactly the routes it asked for and nothing wider.
            ipv4Routes: pushed.redirectGatewayV4 ? [.init("0.0.0.0", 0)] : pushedRoutes,
            ipv4ExcludedRoutes: excluded,
            ipv6Address: v6?.address,
            ipv6Routes: (hasV6 || options.blockIPv6WhenUnavailable) ? [.init("::", 0)] : [],
            ipv6ExcludedRoutes: pushed.routes.filter { $0.exclude && $0.ipv6 }
                .map { TunnelPlan.Route($0.address, $0.prefix) },
            ipv6Blocked: !hasV6 && options.blockIPv6WhenUnavailable,
            // The relay chose these resolvers. We cannot make that private, but
            // an empty push must not silently fall back to the device's own
            // resolver, which would leak every lookup outside the tunnel.
            dnsServers: pushed.dns,
            dnsMatchDomains: [""],
            splitDNSDomains: options.lanSuffixes,
            mtu: pushed.effectiveMTU,
            forwardingEnabled: true)
    }

    /// Whether a packet read from the tunnel interface may be forwarded.
    public func mayForward(state: TunnelState) -> Bool { state.forwardingAllowed }

    /// Whether the OS-level kill switch flags should be set on the VPN profile.
    public var includeAllNetworks: Bool { options.killSwitchEnabled }
    public var excludeLocalNetworks: Bool { options.excludeLocalNetworks }

    /// On-demand catch-all is our App-Store-legal stand-in for always-on.
    public var onDemandEnabled: Bool { options.killSwitchEnabled }

    /// The only parts of the options the VPN *profile* is built from.
    ///
    /// Everything else — the local proxy, whether it exits through the Worker,
    /// the bridge list — lives entirely in the app, and reinstalling a profile
    /// for it is not merely wasted work: with the kill switch on the profile
    /// carries an on-demand connect rule, so saving it brings the tunnel up.
    /// Turning on a loopback proxy would connect the VPN, which is precisely
    /// the opposite of what the Worker exit is for.
    public static func profileInputs(_ o: SecurityPolicyOptions) -> [Bool] {
        [o.killSwitchEnabled, o.excludeLocalNetworks]
    }
}
