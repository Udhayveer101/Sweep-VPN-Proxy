import Foundation
import SwiftUI
import NetworkExtension
import SweepVPNCore
import SweepVPNKit

/// App-side view model. It never decides anything security-relevant — it mirrors
/// the provider's authoritative state and forwards intents.
@MainActor
public final class VPNViewModel: ObservableObject {
    @Published public private(set) var presentation: Presentation
    @Published public private(set) var state: TunnelState = .disconnected
    @Published public private(set) var serverName: String?
    @Published public private(set) var quality: Presentation.Quality?
    @Published public private(set) var killSwitchArmed = true
    @Published public private(set) var onDemandArmed = true
    @Published public private(set) var pqHybridActive = false
    @Published public private(set) var rung: ProtocolRung?
    @Published public private(set) var isBusy = false
    /// One sheet at a time. SwiftUI silently misbehaves when several `.sheet`
    /// modifiers sit on the same view — they fight, and the wrong one wins — so
    /// there is a single presentation slot rather than a bool per screen.
    public enum Sheet: String, Identifiable, Sendable {
        case settings, serverPicker, setupGuide, onboarding
        public var id: String { rawValue }
    }
    @Published public var activeSheet: Sheet?
    @Published public var lastError: String?
    /// Why the app has no usable configuration, shown to the user instead of a
    /// silent "not protected".
    @Published public private(set) var configStatus: String?
    @Published public var options = SecurityPolicyOptions()
    @Published public var preference: ProtocolPreference = .automatic
    @Published public private(set) var servers: [Server] = []
    /// The ordered list the picker renders: Automatic, then the fastest server,
    /// then everything else fastest → slowest.
    @Published public private(set) var listEntries: [ServerListEntry] = []
    @Published public private(set) var selectedServerID: ServerID?
    /// Servers that need an operator account are hidden until the user opts in.
    @Published public var showAccountOnlyServers = false
    /// No verified, unexpired signed bundle => the app has nothing it is allowed
    /// to connect to, and says so instead of implying it is standing guard.
    @Published public private(set) var hasVerifiedConfig = false
    /// Why there is no config: `.notConfigured` (never set up) reads very
    /// differently to the user than `.configurationInvalid` (a bad signature),
    /// so the two must not share one alarming screen.
    @Published public private(set) var configFailureKind: TunnelErrorKind = .notConfigured


    /// Second line on the server pill: which server Automatic landed on, or the
    /// latency of the pinned one.
    public var serverSubtitle: String? {
        if isAutomaticSelected {
            return serverName.map { "Fastest — \($0)" }
        }
        return rung?.displayName
    }

    /// The route actually carrying traffic, shown only while connected so the
    /// user can see when the app has fallen back to a stealth rung.
    public var routeDescription: String? {
        guard state.forwardingAllowed, let rung else { return nil }
        return rung == .wireGuardUDP ? nil : "via \(rung.displayName)"
    }

    public var animateBackdrop: Bool {
        !ProcessInfo.processInfo.isLowPowerModeEnabled && state.forwardingAllowed
    }

    /// Bundle ids the macOS settings pane needs to install/activate extensions.
    public var tunnelExtensionID: String { configurator.bundleIdentifier }
    public var filterExtensionID: String {
        configurator.bundleIdentifier.replacingOccurrences(of: ".tunnel", with: ".filter")
    }

    private let configurator: VPNConfigurator
    private var catalog = ServerCatalog()
    private var pollTask: Task<Void, Never>?

    public init(configurator: VPNConfigurator) {
        self.configurator = configurator
        self.presentation = Presentation.make(state: .disconnected, serverName: nil,
                                              killSwitchArmed: true, onDemandArmed: true, quality: nil)
        if !UserDefaults.standard.bool(forKey: "sweep.onboarded") { activeSheet = .onboarding }
    }

    /// Test/preview seam: force a state without a running extension.
    public func overrideStateForPreview(_ state: TunnelState, rung: ProtocolRung? = nil,
                                        quality: Presentation.Quality? = nil) {
        self.state = state
        self.rung = rung
        self.quality = quality
        recompute()
    }

    public func onAppear() {
        // Status is event-driven off NEVPNStatusDidChange; the timer is only a
        // slow safety net so we never poll hard in the background.
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil,
                                               queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    public func onDisappear() { pollTask?.cancel(); pollTask = nil }

    /// Remembering that the primer was shown is the only thing this app stores
    /// outside the Keychain — it is not a secret and not user data.
    public func completeOnboarding() {
        UserDefaults.standard.set(true, forKey: "sweep.onboarded")
        if activeSheet == .onboarding { activeSheet = nil }
    }

    public func refresh() async {
        guard let response = try? await configurator.send(.getStatus) else {
            applySystemStatus()
            return
        }
        if case .servers(let ranked) = try? await configurator.send(.getServers) {
            apply(ranked: ranked)
        }
        if case .status(let s) = response {
            state = s.state
            serverName = s.serverName
            killSwitchArmed = s.killSwitchArmed
            onDemandArmed = options.killSwitchEnabled
            pqHybridActive = s.pqHybridActive
            rung = s.rung
            quality = s.rttMs.map { Presentation.Quality.from(rttMs: $0, lossFraction: 0) }
            recompute()
        }
    }

    /// If the extension is not running we still must not show "off" when the
    /// system says the tunnel is in a failed state.
    private func applySystemStatus() {
        switch configurator.connectionStatus {
        case .connected: state = .connected(rung: .wireGuardUDP, server: serverName ?? "")
        case .connecting, .reasserting: state = .connecting(rung: .wireGuardUDP)
        case .disconnecting: state = .reconnecting(attempt: 0)
        case .invalid: state = .error(.systemDenied)
        default:
            if !hasVerifiedConfig { state = .error(configFailureKind) }
            else { state = options.killSwitchEnabled ? .onDemandArmed : .disconnected }
        }
        recompute()
    }

    private func recompute() {
        presentation = Presentation.make(state: state, serverName: serverName,
                                         killSwitchArmed: killSwitchArmed,
                                         onDemandArmed: onDemandArmed, quality: quality)
    }

    public func perform(_ action: Presentation.Action) {
        Task { await run(action) }
    }

    private func run(_ action: Presentation.Action) async {
        isBusy = true
        defer { isBusy = false }
        do {
            switch action {
            case .connect, .retry:
                try await configurator.install(policy: SecurityPolicy(options: options),
                                               serverDescription: serverName ?? "Sweep VPN")
                try await configurator.start()
            case .disconnect, .cancel:
                try await configurator.stop()
            case .openSettings:
                // The same button means two different things: finish setup, or
                // re-grant a VPN permission the user revoked.
                if configFailureKind == .notConfigured && !hasVerifiedConfig {
                    activeSheet = .setupGuide
                } else {
                    openSystemSettings()
                }
            }
            await refresh()
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func apply(options newOptions: SecurityPolicyOptions) {
        options = newOptions
        Task {
            _ = try? await configurator.send(.setSecurityOptions(newOptions))
            try? await configurator.install(policy: SecurityPolicy(options: newOptions),
                                            serverDescription: serverName ?? "Sweep VPN")
            await refresh()
        }
    }

    /// Modes a user can pick directly; `forced` is set from the Advanced picker.
    public static let selectableModes: [ProtocolPreference] = [.automatic, .fast, .stealth, .lowPower]

    /// Rungs this build can actually run, in ladder order.
    public var selectableRungs: [ProtocolRung] {
        ProtocolRung.allCases.filter(AdapterFactory.availableRungs.contains)
    }

    public var forcedRung: ProtocolRung? {
        if case .forced(let r) = preference { return r }
        return nil
    }

    public func apply(forcedRung rung: ProtocolRung?) {
        apply(preference: rung.map { ProtocolPreference.forced($0) } ?? .automatic)
    }

    public func apply(preference newPreference: ProtocolPreference) {
        preference = newPreference
        Task {
            _ = try? await configurator.send(.setPreference(newPreference))
            await refresh()
        }
    }

    /// Record a configuration problem — the app must never look idle-but-fine
    /// when it simply could not get a verified server list.
    public func noteConfigurationFailure(_ description: String,
                                        kind: TunnelErrorKind = .configurationInvalid) {
        configStatus = description
        configFailureKind = kind
        hasVerifiedConfig = false
        applySystemStatus()
    }

    public func noteConfigurationLoaded(version: UInt64, servers: Int) {
        configStatus = "Configuration v\(version), \(servers) servers"
    }

    public func load(servers: [Server]) {
        self.servers = servers
        hasVerifiedConfig = !servers.isEmpty
        if !servers.isEmpty { configFailureKind = .notConfigured }
        catalog.replaceServers(servers)
        rebuildList()
        applySystemStatus()
    }

    /// Merge the measurements the extension reports into the local catalog, so
    /// the ordering the user sees is the ordering the tunnel actually uses.
    public func apply(ranked: [RankedServer]) {
        catalog.replaceServers(ranked.map(\.server))
        for row in ranked {
            guard let rtt = row.rttMs else { continue }
            catalog.record(ServerProbe(rttMs: rtt, lossFraction: row.lossFraction ?? 0), for: row.id)
        }
        servers = ranked.map(\.server)
        hasVerifiedConfig = !servers.isEmpty
        rebuildList()
    }

    private func rebuildList() {
        listEntries = catalog.listEntries(includeAccountRequired: showAccountOnlyServers)
        // "Automatic" means the fastest measured server, re-evaluated as
        // measurements arrive — the name shown must follow it.
        if selectedServerID == nil || selectedServerID == automaticID {
            serverName = catalog.fastest(includeAccountRequired: showAccountOnlyServers)?.name
        }
        recompute()
    }

    public let automaticID: ServerID = "__automatic__"

    public var isAutomaticSelected: Bool { selectedServerID == nil || selectedServerID == automaticID }

    public func selectAutomatic() {
        selectedServerID = automaticID
        serverName = catalog.fastest(includeAccountRequired: showAccountOnlyServers)?.name
        recompute()
        Task { _ = try? await configurator.send(.reconnect) }
    }

    public func select(server: Server) {
        selectedServerID = server.id
        serverName = server.name
        recompute()
        Task { _ = try? await configurator.send(.selectServer(server.id)) }
    }

    public func setShowAccountOnlyServers(_ show: Bool) {
        showAccountOnlyServers = show
        rebuildList()
    }

    public func exportDiagnostics() async -> String {
        guard case .diagnostics(let events)? = try? await configurator.send(.exportDiagnostics) else {
            return "No diagnostics available."
        }
        return events.map { "\($0.at) \($0.kind) \($0.detail)" }.joined(separator: "\n")
    }

    private func openSystemSettings() {
        #if os(iOS)
        if let url = URL(string: "App-Prefs:root=General&path=VPN") ?? URL(string: UIApplication.openSettingsURLString) {
            UIApplication.shared.open(url)
        }
        #else
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.network") {
            NSWorkspace.shared.open(url)
        }
        #endif
    }
}

#if os(iOS)
import UIKit
#else
import AppKit
#endif
