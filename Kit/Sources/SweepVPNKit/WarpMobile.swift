#if os(iOS)
import Foundation
import NetworkExtension
import SweepVPNCore
import SweepWarpC

/// iOS WARP. Same tunnel as macOS (patched usque, HTTP/2 MASQUE with a neutral
/// SNI), but iOS has no child processes and no system SOCKS proxy, so it runs
/// inside a packet-tunnel extension (`WarpPacketTunnelProvider`) linked against
/// SweepWarp.xcframework, and this controller drives that extension's VPN
/// profile. The effect is the macOS "Route this whole Mac through WARP" switch,
/// covering every app rather than only proxy-aware ones.
public final class WarpController: @unchecked Sendable {

    public enum State: Equatable, Sendable {
        case stopped
        case starting
        case running                 // tunnel up and carrying traffic
        case failed(String)

        public var isFailed: Bool { if case .failed = self { return true }; return false }
    }

    public static let providerBundleIdentifier = "com.sweep.vpn.ios.warp"

    /// Shared app-group container, so the app registers and the extension reads.
    public static var defaultDirectory: URL {
        let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppGroupID.resolved)
            ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("warp", isDirectory: true)
    }

    public let sni: String
    private var observer: NSObjectProtocol?
    private var onState: (@Sendable (State) -> Void)?

    public init(sni: String = "example.com") { self.sni = sni }

    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }

    /// Saves (or refreshes) the WARP profile, then starts it. iOS shows its
    /// "Add VPN Configurations" prompt the first time.
    public func start(onState: @escaping @Sendable (State) -> Void) {
        self.onState = onState
        guard WarpRegistration.isRegistered() else {
            onState(.failed("WARP is not set up yet. Open Settings ▸ WARP setup and press Register."))
            return
        }
        onState(.starting)
        Task {
            do {
                let manager = try await Self.loadOrCreateManager()
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = Self.providerBundleIdentifier
                proto.serverAddress = "Cloudflare WARP (SNI \(sni))"
                proto.providerConfiguration = ["sni": sni]
                manager.protocolConfiguration = proto
                manager.localizedDescription = "Sweep WARP"
                manager.isEnabled = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
                observe(manager)
                EventLog.shared.record(phase: "warp", kind: "starting", detail: "sni=\(sni)")
                try manager.connection.startVPNTunnel()
            } catch {
                EventLog.shared.record(phase: "warp", level: .error, kind: "startFailed",
                                       detail: error.localizedDescription)
                onState(.failed(Self.describe(error)))
            }
        }
    }

    public func stop() {
        Task {
            guard let manager = try? await Self.existingManager() else {
                onState?(.stopped)
                return
            }
            EventLog.shared.record(phase: "warp", kind: "stopped", detail: "asked to stop")
            manager.connection.stopVPNTunnel()
        }
    }

    /// Reports the tunnel's current state without starting it: the extension
    /// outlives the app, so a relaunch has to pick up a tunnel already running.
    public func attach(onState: @escaping @Sendable (State) -> Void) {
        self.onState = onState
        Task {
            guard let manager = try? await Self.existingManager() else { return }
            observe(manager)
        }
    }

    private func observe(_ manager: NETunnelProviderManager) {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        let connection = manager.connection
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange,
                                                          object: connection, queue: nil) { [weak self] _ in
            self?.report(connection)
        }
        report(connection)
    }

    private func report(_ connection: NEVPNConnection) {
        switch connection.status {
        case .connecting, .reasserting: onState?(.starting)
        case .connected: onState?(.running)
        case .disconnecting: onState?(.stopped)
        case .invalid: onState?(.stopped)
        case .disconnected:
            connection.fetchLastDisconnectError { [weak self] error in
                // A user-initiated stop carries no error.
                if let error { self?.onState?(.failed(Self.describe(error))) }
                else { self?.onState?(.stopped) }
            }
        @unknown default: onState?(.stopped)
        }
    }

    private static func describe(_ error: Error) -> String {
        let ns = error as NSError
        if ns.domain == NEVPNErrorDomain, ns.code == NEVPNError.configurationReadWriteFailed.rawValue {
            return "iOS did not allow the VPN configuration. Tap the switch again and choose Allow."
        }
        return error.localizedDescription
    }

    private static func existingManager() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == providerBundleIdentifier
        }
    }

    private static func loadOrCreateManager() async throws -> NETunnelProviderManager {
        try await existingManager() ?? NETunnelProviderManager()
    }
}

extension WarpRegistration {
    /// Registers this device with WARP in-process (the same calls as
    /// `usque register`), then binds the license key if one was given. Only
    /// call after the user accepted Cloudflare's terms. A failed license
    /// leaves the (working, free) registration in place.
    public static func register(licenseKey: String = "", teamToken: String = "",
                                directory: URL = WarpController.defaultDirectory) async throws {
        let key = try validated(licenseKey: licenseKey)
        let token = teamToken.trimmingCharacters(in: .whitespacesAndNewlines)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let configFile = directory.appendingPathComponent("config.json")
        if !isRegistered(directory: directory) {
            try await call("Registration") {
                SweepWarpRegister(strdup(configFile.path), strdup("Sweep VPN"), strdup(token))
            }
            guard isRegistered(directory: directory) else {
                throw Failure(message: "Registration finished but no WARP configuration was saved. Try again.")
            }
            EventLog.shared.record(phase: "warp", kind: "registered", detail: token.isEmpty ? "free" : "team")
        }
        if !key.isEmpty {
            try await call("Setting the license key") {
                SweepWarpSetLicense(strdup(configFile.path), strdup(key))
            }
            EventLog.shared.record(phase: "warp", kind: "licenseSet", detail: "WARP+ key bound")
        }
    }

    /// The Go calls block on the network, so they run off the main actor. The
    /// strdup'd arguments are leaked deliberately: a few bytes, once per setup.
    private static func call(_ what: String, _ body: @escaping @Sendable () -> UnsafeMutablePointer<CChar>?) async throws {
        let message: String? = await Task.detached {
            guard let result = body() else { return nil }
            defer { SweepWarpFree(result) }
            return String(cString: result)
        }.value
        guard let message else { return }
        EventLog.shared.record(phase: "warp", level: .error, kind: "setupFailed", detail: message)
        throw Failure(message: "\(what) failed: \(message). Check your internet connection and any key you entered, then try again.")
    }
}

/// The addresses Cloudflare assigned at registration, read from usque's config.
struct WarpInterface: Decodable {
    let ipv4: String
    let ipv6: String
    let endpointH2V4: String

    enum CodingKeys: String, CodingKey {
        case ipv4, ipv6
        case endpointH2V4 = "endpoint_h2_v4"
    }
}

/// The WARP packet tunnel. Subclassed (empty) by the extension target.
open class WarpPacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    /// usque logs through a C callback that cannot capture context.
    nonisolated(unsafe) fileprivate static weak var current: WarpPacketTunnelProvider?

    private let lock = NSLock()
    private var pendingStart: ((Error?) -> Void)?
    private var lastError: String?
    private var startDeadline: DispatchWorkItem?

    /// Same budget as the macOS stall watchdog.
    static let startTimeout: TimeInterval = 30

    open override func startTunnel(options: [String: NSObject]?,
                                   completionHandler: @escaping (Error?) -> Void) {
        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let sni = (proto?.providerConfiguration?["sni"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "example.com"
        let configFile = WarpController.defaultDirectory.appendingPathComponent("config.json")

        guard let data = try? Data(contentsOf: configFile),
              let iface = try? JSONDecoder().decode(WarpInterface.self, from: data) else {
            return completionHandler(Self.error("WARP is not set up yet. Open Sweep and register first."))
        }

        Self.current = self
        SweepWarpSetLogger { line in
            guard let line else { return }
            WarpPacketTunnelProvider.current?.ingest(String(cString: line))
        }

        setTunnelNetworkSettings(Self.settings(for: iface)) { [weak self] error in
            guard let self else { return }
            if let error {
                EventLog.shared.record(phase: "warp", level: .error, kind: "settingsRejected",
                                       detail: "\(error.localizedDescription) remote=\(Self.remoteAddress(iface.endpointH2V4)) v4=\(iface.ipv4) v6=\(iface.ipv6.isEmpty ? "none" : "set")")
                return completionHandler(error)
            }
            let fd = SweepWarpFindTunnelFd()
            guard fd >= 0 else { return completionHandler(Self.error("Could not find the tunnel interface.")) }

            self.lock.lock()
            self.pendingStart = completionHandler
            let deadline = DispatchWorkItem { [weak self] in self?.startTimedOut() }
            self.startDeadline = deadline
            self.lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + Self.startTimeout, execute: deadline)

            EventLog.shared.record(phase: "warp", kind: "starting", detail: "sni=\(sni)")
            if let failure = SweepWarpStart(strdup(configFile.path), strdup(sni), fd) {
                let message = String(cString: failure)
                SweepWarpFree(failure)
                self.finishStart(Self.error("Could not start WARP: \(message)"))
            }
        }
    }

    open override func stopTunnel(with reason: NEProviderStopReason,
                                  completionHandler: @escaping () -> Void) {
        EventLog.shared.record(phase: "warp", kind: "stopped", detail: "reason \(reason.rawValue)")
        SweepWarpStop()
        finishStart(Self.error("Stopped before WARP connected."))
        completionHandler()
    }

    /// Full-device route. IPv6 is claimed too so it cannot leak around the
    /// tunnel; the data plane drops it (it does not route inside the session).
    /// DNS goes to Cloudflare through the tunnel, the same resolvers macOS pins.
    static func settings(for iface: WarpInterface) -> NEPacketTunnelNetworkSettings {
        // iOS rejects anything but a bare IP here ("Invalid NETunnelNetworkSettings
        // tunnelRemoteAddress"); the value is only a label, the fd carries traffic.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress(iface.endpointH2V4))
        let v4 = NEIPv4Settings(addresses: [iface.ipv4], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = v4
        if !iface.ipv6.isEmpty {
            let v6 = NEIPv6Settings(addresses: [iface.ipv6], networkPrefixLengths: [128])
            v6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = v6
        }
        let dns = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1280
        return settings
    }

    /// Bare IPv4/IPv6 from the config value (tolerating "ip:port" and "[v6]:port"),
    /// else Cloudflare's default HTTP/2 MASQUE endpoint.
    static func remoteAddress(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("["), let end = s.firstIndex(of: "]") {
            s = String(s[s.index(after: s.startIndex)..<end])
        } else if s.filter({ $0 == ":" }).count == 1, let colon = s.firstIndex(of: ":") {
            s = String(s[..<colon])
        }
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1 { return s }
        return "162.159.198.2"
    }

    func ingest(_ line: String) {
        switch WarpController.classify(line) {
        case .connected:
            EventLog.shared.record(phase: "warp", kind: "connected", detail: line)
            reasserting = false
            finishStart(nil)
        case .lost:
            EventLog.shared.record(phase: "warp", level: .warn, kind: "lost", detail: line)
            reasserting = true
        case .error:
            EventLog.shared.record(phase: "warp", level: .warn, kind: "log", detail: line)
            lock.lock(); lastError = line; lock.unlock()
        case .listening, nil:
            EventLog.shared.record(phase: "warp", kind: "log", detail: line)
        }
    }

    private func startTimedOut() {
        lock.lock(); let why = lastError; lock.unlock()
        EventLog.shared.record(phase: "warp", level: .error, kind: "stalled",
                               detail: "not connected after \(Int(Self.startTimeout))s")
        SweepWarpStop()
        finishStart(Self.error("WARP did not connect within \(Int(Self.startTimeout)) seconds"
                               + (why.map { ": \($0)" } ?? ".")))
    }

    private func finishStart(_ error: Error?) {
        lock.lock()
        let handler = pendingStart
        pendingStart = nil
        startDeadline?.cancel()
        startDeadline = nil
        lock.unlock()
        handler?(error)
    }

    static func error(_ message: String) -> NSError {
        NSError(domain: "SweepWarp", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
#endif
