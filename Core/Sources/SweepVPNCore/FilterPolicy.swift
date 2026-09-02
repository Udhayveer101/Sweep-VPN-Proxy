import Foundation

/// macOS-only second kill-switch layer: a decision function for a
/// `NEFilterDataProvider` that blocks by default and keys on the *interface*,
/// not on the routing table.
///
/// Routing alone is not a kill switch on macOS: TunnelVision (CVE-2024-3661)
/// lets a rogue DHCP server inject more-specific routes that pull traffic off a
/// tunnel that still reads as "connected".
///
/// Limit, stated plainly: `NEFilterFlow` does **not** expose the interface a
/// flow will use, so when the tunnel is up this filter cannot tell a hijacked
/// flow from a tunnelled one and allows it. What it does enforce absolutely is
/// the case that matters most — while the tunnel is *not* up, every flow except
/// loopback, permitted LAN and the tunnel's own handshake is dropped,
/// independently of what the routing table says. If a future OS exposes the
/// interface, `Flow.interfaceName` is already wired through and the stricter
/// rule below takes effect with no other change.
public struct FilterPolicy: Sendable, Equatable {
    public enum Verdict: String, Sendable, Equatable {
        case allow          // on the tunnel interface, or an explicitly permitted flow
        case drop           // blocked: fail closed
    }

    /// The facts the filter provider can see about a flow.
    public struct Flow: Sendable, Equatable {
        public var interfaceName: String?
        public var remoteAddress: String?
        public var isLoopback: Bool
        public var isOutbound: Bool

        public init(interfaceName: String?, remoteAddress: String?,
                    isLoopback: Bool = false, isOutbound: Bool = true) {
            self.interfaceName = interfaceName
            self.remoteAddress = remoteAddress
            self.isLoopback = isLoopback
            self.isOutbound = isOutbound
        }
    }

    public var options: SecurityPolicyOptions
    /// The utun interface the tunnel is currently on, if any.
    public var tunnelInterface: String?
    /// Whether the tunnel is authenticated and forwarding right now.
    public var tunnelIsUp: Bool
    /// Endpoint of the server we are dialling: this flow must be allowed out on
    /// the physical interface or the tunnel could never be established.
    public var serverAddresses: Set<String>

    public init(options: SecurityPolicyOptions = .init(), tunnelInterface: String? = nil,
                tunnelIsUp: Bool = false, serverAddresses: Set<String> = []) {
        self.options = options
        self.tunnelInterface = tunnelInterface
        self.tunnelIsUp = tunnelIsUp
        self.serverAddresses = serverAddresses
    }

    public func verdict(for flow: Flow) -> Verdict {
        if flow.isLoopback { return .allow }

        // The blocklist is checked before every other rule, including the kill
        // switch. A domain the user has blocked must stay blocked when the VPN
        // is off — that is the whole point of it, and an in-tunnel DNS filter
        // cannot do it because with the tunnel down there is no in-tunnel DNS.
        if let host = flow.remoteAddress, Self.isBlocked(host, by: options.blockedDomains) {
            return .drop
        }

        // With the kill switch off the filter is not an enforcement point.
        guard options.killSwitchEnabled else { return .allow }

        // The tunnel's own packets to the server must always get out, or there
        // is no way back up from a blocked state.
        if let remote = flow.remoteAddress, serverAddresses.contains(remote) { return .allow }

        // LAN stays reachable only if the user asked for it.
        if options.excludeLocalNetworks, let remote = flow.remoteAddress,
           FilterPolicy.isPrivate(remote) {
            return .allow
        }

        // Fail closed whenever the tunnel is not carrying traffic.
        guard tunnelIsUp else { return .drop }

        // When the OS tells us which interface the flow will use, require it to
        // be the tunnel; that is the route-independent check.
        if let tunnel = tunnelInterface, let iface = flow.interfaceName, iface != tunnel {
            return .drop
        }
        return .allow
    }

    /// Suffix match on domain-label boundaries. Plain `hasSuffix` would let
    /// "notevil.com" be blocked by a rule for "evil.com", and — worse — would
    /// let "evil.com.attacker.net" slip past a rule for "evil.com".
    public static func isBlocked(_ host: String, by blocked: [String]) -> Bool {
        guard !blocked.isEmpty else { return false }
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        for rule in blocked {
            let r = rule.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
            guard !r.isEmpty else { continue }
            if h == r { return true }
            if h.hasSuffix("." + r) { return true }
        }
        return false
    }

    /// RFC1918 / link-local / unique-local ranges — the only addresses that may
    /// bypass the tunnel when local network access is on.
    public static func isPrivate(_ address: String) -> Bool {
        if address.hasPrefix("10.") || address.hasPrefix("192.168.") { return true }
        if address.hasPrefix("169.254.") { return true }
        if address.hasPrefix("127.") || address == "::1" { return true }
        if address.lowercased().hasPrefix("fe80:") { return true }
        if address.lowercased().hasPrefix("fd") || address.lowercased().hasPrefix("fc") { return true }
        if address.hasPrefix("172.") {
            let parts = address.split(separator: ".")
            if parts.count > 1, let second = Int(parts[1]), (16...31).contains(second) { return true }
        }
        if address.hasPrefix("224.") || address.hasPrefix("239.") { return true }   // multicast (Bonjour)
        return false
    }
}
