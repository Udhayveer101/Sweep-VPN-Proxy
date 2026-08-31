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
    @Published public private(set) var isBusy = false
    @Published public var showSettings = false
    @Published public var showServerPicker = false
    @Published public var lastError: String?
    @Published public var options = SecurityPolicyOptions()
    @Published public var preference: ProtocolPreference = .automatic
    @Published public private(set) var servers: [Server] = []
    /// No verified, unexpired signed bundle => the app has nothing it is allowed
    /// to connect to, and says so instead of implying it is standing guard.
    @Published public private(set) var hasVerifiedConfig = false

    public var animateBackdrop: Bool {
        !ProcessInfo.processInfo.isLowPowerModeEnabled && state.forwardingAllowed
    }

    private let configurator: VPNConfigurator
    private var pollTask: Task<Void, Never>?

    public init(configurator: VPNConfigurator) {
        self.configurator = configurator
        self.presentation = Presentation.make(state: .disconnected, serverName: nil,
                                              killSwitchArmed: true, onDemandArmed: true, quality: nil)
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

    public func refresh() async {
        guard let response = try? await configurator.send(.getStatus) else {
            applySystemStatus()
            return
        }
        if case .status(let s) = response {
            state = s.state
            serverName = s.serverName
            killSwitchArmed = s.killSwitchArmed
            onDemandArmed = options.killSwitchEnabled
            pqHybridActive = s.pqHybridActive
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
            if !hasVerifiedConfig { state = .error(.configurationInvalid) }
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
                openSystemSettings()
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

    public func apply(preference newPreference: ProtocolPreference) {
        preference = newPreference
        Task {
            _ = try? await configurator.send(.setPreference(newPreference))
            await refresh()
        }
    }

    public func load(servers: [Server]) {
        self.servers = servers
        hasVerifiedConfig = !servers.isEmpty
        if serverName == nil { serverName = servers.first?.name }
        applySystemStatus()
    }

    public func select(server: Server) {
        serverName = server.name
        recompute()
        Task { _ = try? await configurator.send(.reconnect) }
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
