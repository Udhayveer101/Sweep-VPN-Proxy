// FilterState below the #endif is shared with the iOS tunnel provider, so the
// imports it needs must sit outside the macOS-only guard.
import Foundation
import NetworkExtension
import SweepVPNCore

#if os(macOS)

/// macOS second kill-switch layer. Runs as a content-filter system extension and
/// drops every flow that is not on the live tunnel interface, independently of
/// the routing table — which is what defeats route-injection attacks like
/// TunnelVision (vault 05-Security/Kill-Switch-Design-macOS).
///
/// It is deliberately dumb and offline: no flow metadata leaves this process,
/// nothing is logged about destinations, and the decision function itself lives
/// in `FilterPolicy` in the shared core so it can be unit-tested.
open class SweepFilterDataProvider: NEFilterDataProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var policy = FilterPolicy()

    /// The provider reads its state from the App Group defaults the tunnel
    /// writes to; nothing else can change the verdict.
    open var stateStore: FilterStateStore? { nil }

    open override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        refreshPolicy()
        // Block-by-default: every new flow is examined, and while the tunnel is
        // down every examined flow is dropped.
        let rule = NENetworkRule(__remoteNetwork: nil, remotePrefix: 0, localNetwork: nil,
                                 localPrefix: 0, protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: rule, action: .filterData)],
                                        defaultAction: .filterData)
        apply(settings) { error in completionHandler(error) }
    }

    open override func stopFilter(with reason: NEProviderStopReason,
                                  completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    open override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        refreshPolicy()
        let socket = flow as? NEFilterSocketFlow
        let remote = socket.flatMap { Self.remoteAddress(of: $0) }
        let candidate = FilterPolicy.Flow(
            interfaceName: flowInterfaceName(flow),
            remoteAddress: remote,
            remoteHostname: Self.remoteHostname(of: flow, socket: socket),
            isLoopback: remote.map { $0 == "127.0.0.1" || $0 == "::1" } ?? false,
            isOutbound: socket?.direction != .inbound)

        lock.lock()
        let verdict = policy.verdict(for: candidate)
        lock.unlock()
        return verdict == .allow ? .allow() : .drop()
    }

    /// Pull the remote address out of whichever endpoint API this OS provides.
    ///
    /// The macOS 15 path alone was not enough: the deployment target is macOS
    /// 14, where this returned nil for *every* flow. That is not a cosmetic gap
    /// — with the kill switch armed and the tunnel down, `serverAddresses`
    /// could never match, so the filter dropped the tunnel's own handshake and
    /// the VPN could never connect at all. `remoteEndpoint` is deprecated but
    /// present back to 10.15 and answers the same question.
    static func remoteAddress(of flow: NEFilterSocketFlow) -> String? {
        if #available(macOS 15.0, *), let endpoint = flow.remoteFlowEndpoint {
            // Match the endpoint rather than parsing its description, whose
            // format is not contractual and quietly changed shape before.
            if case .hostPort(let host, _) = endpoint {
                switch host {
                case .ipv4(let address): return "\(address)"
                // Scoped v6 addresses render as "fe80::1%en0".
                case .ipv6(let address): return "\(address)".split(separator: "%").first.map(String.init)
                case .name(let name, _): return name
                @unknown default: return nil
                }
            }
            return nil
        }
        // macOS 14 has no `remoteFlowEndpoint`, and its predecessor
        // (`remoteEndpoint`/`NWHostEndpoint`) is not surfaced to Swift at all,
        // so it is read through KVC. Both are plain Objective-C objects, and
        // returning nil here is not cosmetic: with the kill switch armed the
        // filter would have no address to match `serverAddresses` against and
        // would drop the tunnel's own handshake, so the VPN could never come up.
        return (flow.value(forKey: "remoteEndpoint") as? NSObject)?
            .value(forKey: "hostname") as? String
    }

    /// The hostname the flow is for, when the OS knows it. Required for domain
    /// rules: `remoteAddress` is an address, so matching "ads.example.com"
    /// against it never fired and the blocklist silently did nothing.
    static func remoteHostname(of flow: NEFilterFlow, socket: NEFilterSocketFlow?) -> String? {
        if #available(macOS 11.0, *), let name = socket?.remoteHostname, !name.isEmpty {
            return name
        }
        return flow.url?.host
    }

    /// `NEFilterFlow` does not publish the interface a flow will use. We keep
    /// the hook so the stricter, route-independent rule switches on for free if
    /// a future OS exposes it — see `FilterPolicy` for what that changes.
    private func flowInterfaceName(_ flow: NEFilterFlow) -> String? { nil }

    private func refreshPolicy() {
        guard let state = stateStore?.read() else { return }
        lock.lock()
        policy = FilterPolicy(options: state.options, tunnelInterface: state.tunnelInterface,
                              tunnelIsUp: state.tunnelIsUp, serverAddresses: state.serverAddresses)
        lock.unlock()
    }
}
#endif

/// The tiny piece of state the packet-tunnel shares with the content filter:
/// which interface the tunnel is on, whether it is up, and the server addresses
/// that must stay reachable. It carries no user data.
public struct FilterState: Codable, Sendable, Equatable {
    public var tunnelInterface: String?
    public var tunnelIsUp: Bool
    public var serverAddresses: Set<String>
    public var options: SecurityPolicyOptions

    public init(tunnelInterface: String?, tunnelIsUp: Bool,
                serverAddresses: Set<String>, options: SecurityPolicyOptions) {
        self.tunnelInterface = tunnelInterface
        self.tunnelIsUp = tunnelIsUp
        self.serverAddresses = serverAddresses
        self.options = options
    }

    /// The safe value to assume when nothing has been published yet.
    public static let failClosed = FilterState(tunnelInterface: nil, tunnelIsUp: false,
                                               serverAddresses: [], options: .init())
}

/// App-Group-backed handoff between the tunnel and the filter.
public struct FilterStateStore: @unchecked Sendable {
    private static let key = "sweep.filter.state"
    private let appGroup: String

    public init(appGroup: String) { self.appGroup = appGroup }

    private var defaults: UserDefaults? { UserDefaults(suiteName: appGroup) }

    public func write(_ state: FilterState) {
        guard let data = try? IPCCodec.encode(state) else { return }
        defaults?.set(data, forKey: Self.key)
    }

    /// Reading a missing or corrupt value returns the fail-closed state, so a
    /// filter that cannot see the tunnel blocks rather than opens.
    public func read() -> FilterState {
        guard let data = defaults?.data(forKey: Self.key),
              let state = try? IPCCodec.decode(FilterState.self, data) else {
            return .failClosed
        }
        return state
    }
}
