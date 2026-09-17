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
    /// Live data-plane figures behind the Security panel. Nil handshake age means
    /// no handshake has completed, which is not the same as "0 seconds ago".
    @Published public private(set) var handshakeAgeSeconds: Int64?
    @Published public private(set) var bytesSent: UInt64 = 0
    @Published public private(set) var bytesReceived: UInt64 = 0
    /// Short fingerprint of the pinned config-signing key, shown so the user can
    /// compare it against the key they generated. Set by the app at startup.
    @Published public var signingKeyFingerprint: String?
    @Published public private(set) var rung: ProtocolRung?
    /// Transient note shown when Automatic walks the ladder to a different
    /// transport, so a fallback reads as a deliberate switch rather than the
    /// connection misbehaving. Cleared a few seconds after it is set.
    @Published public private(set) var protocolSwitchNote: String?
    private var lastSeenRung: ProtocolRung?
    private var protocolNoteClearTask: Task<Void, Never>?
    @Published public private(set) var isBusy = false

    /// The shared journal, written by this process and by the extension.
    let log = EventLog.shared
    /// Snapshot of the journal for the log screen. Republished on a timer while
    /// that screen is open, so a connect that is still running can be watched as
    /// it happens rather than read only after it has failed.
    @Published public private(set) var logEntries: [LogEntry] = []
    private var logTask: Task<Void, Never>?
    /// One sheet at a time. SwiftUI silently misbehaves when several `.sheet`
    /// modifiers sit on the same view — they fight, and the wrong one wins — so
    /// there is a single presentation slot rather than a bool per screen.
    public enum Sheet: String, Identifiable, Sendable {
        case settings, serverPicker, publicRelays, setupGuide, onboarding, connectionLog
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

    // MARK: - VPN Gate public relays

    /// Third-party OpenVPN relays from the VPN Gate public list. Kept in their
    /// own property, not merged into `servers`, because they come from a
    /// different trust world: unsigned, volunteer-run, and not something
    /// `Automatic` will ever select. The user opts in to seeing them.
    @Published public private(set) var relays: [Server] = []
    @Published public var showPublicRelays = false
    @Published public private(set) var relaysFetchedAt: Date?
    @Published public private(set) var relayStatus: String?
    @Published public private(set) var isRefreshingRelays = false
    @Published public private(set) var isProbingRelays = false
    /// Measured RTT per relay, filled in by `probeRelays`.
    @Published public private(set) var relayProbes: [ServerID: ServerProbe] = [:]

    /// Optional user-supplied mirror for the relay list, for networks whose
    /// filter blocks vpngate.net by category (an Indian residential ISP returns
    /// a 403 block page for it).
    @Published public var relaySourceURL: String = UserDefaults.standard
        .string(forKey: "sweep.relaySource") ?? ""

    #if os(macOS)
    /// Your own relay Worker, editable in the running app. No build ships one,
    /// so for anyone who installed a release rather than building it themselves
    /// this is the only way to turn the WSS leg on — and it has to survive an
    /// app update, which is why it lives in the app group and not in the bundle.
    @Published public var workerURLText: String = ""
    @Published public var workerToken: String = ""

    public func loadWorkerSettings() {
        let settings = RelayTunnelSettings.load(appGroup: appGroup)
        guard settings.enabled else { return }   // unconfigured: leave both blank
        workerURLText = settings.workerURL.absoluteString
        workerToken = settings.token
    }

    /// Trimmed, because a pasted URL arrives with whitespace often enough, and a
    /// token with a trailing newline fails the Worker's compare with no clue why.
    public func saveWorkerSettings() {
        let url = workerURLText.trimmingCharacters(in: .whitespacesAndNewlines)
        let token = workerToken.trimmingCharacters(in: .whitespacesAndNewlines)
        workerURLText = url
        workerToken = token
        guard let parsed = URL(string: url), !url.isEmpty, !token.isEmpty else {
            // Clearing either field turns the leg off rather than leaving half a
            // configuration that fails at connect time.
            RelayTunnelSettings(enabled: false,
                                workerURL: WebSocketTransport.unconfiguredWorkerURL,
                                token: "").save(appGroup: appGroup)
            return
        }
        RelayTunnelSettings(enabled: true, workerURL: parsed, token: token)
            .save(appGroup: appGroup)
    }
    #endif

    #if os(macOS)
    @Published public private(set) var torState: TorController.State = .stopped
    @Published public private(set) var proxyState: LocalProxy.State = .stopped
    private var tor: TorController?
    private var proxy: LocalProxy?

    /// Tor bootstrap is a foreground concern: on a network that blocks Tor it can
    /// sit at 14% indefinitely, and a spinner with no number reads as a hang.
    public var torProgressText: String? {
        switch torState {
        case .stopped: return nil
        case .starting(let pct, let summary): return "Tor \(pct)% — \(summary)"
        case .running: return "Tor ready on 127.0.0.1:\(tor?.socksPort ?? 9150)"
        case .failed(let why): return why
        }
    }

    @Published public internal(set) var warpState: WarpController.State = .stopped
    private var warp: WarpController?

    /// Whether this Mac has a WARP registration. Onboarding is shown until it does.
    @Published public internal(set) var warpRegistered = WarpRegistration.isRegistered()
    @Published public private(set) var warpSetupBusy = false
    @Published public var warpSetupError: String?

    /// Runs the in-app registration. The caller must only offer this after the
    /// user ticked the Cloudflare terms box.
    public func registerWarp(licenseKey: String, teamToken: String) async {
        warpSetupBusy = true
        warpSetupError = nil
        defer { warpSetupBusy = false }
        do {
            try await WarpRegistration.register(licenseKey: licenseKey, teamToken: teamToken)
        } catch {
            warpSetupError = error.localizedDescription
        }
        warpRegistered = WarpRegistration.isRegistered()
        if warpRegistered, warpSetupError == nil {
            completeOnboarding()
        }
    }

    public var warpStatusText: String? {
        switch warpState {
        case .stopped: return nil
        case .starting: return "Starting WARP…"
        case .running: return "WARP ready on 127.0.0.1:\(String(options.warpSocksPort)) (SNI \(options.warpSNI))"
        case .failed(let why): return why
        }
    }

    /// The Developer ID release ships without the VPN extensions (SweepProxyOnly
    /// in Info.plist), so its screens offer the proxy instead of Connect.
    public let proxyOnly = Bundle.main.object(forInfoDictionaryKey: "SweepProxyOnly") as? String == "YES"

    @Published public private(set) var systemProxyEnabled = false
    @Published public private(set) var systemProxyError: String?
    /// Set while WARP is still starting and the whole Mac is meant to follow it.
    private var armSystemProxyWhenReady = false

    /// One switch for "send this whole Mac through WARP": start WARP, start the
    /// local proxy, and point the system SOCKS setting at it once WARP is
    /// actually up. Pointing the system at a port nothing is listening on
    /// breaks every app on the machine, so the order matters.
    public func setEverythingThroughWarp(_ on: Bool) {
        systemProxyError = nil
        guard on else {
            armSystemProxyWhenReady = false
            applySystemProxy(false)
            setLocalProxy(enabled: false)
            setWarp(enabled: false)
            return
        }
        if game != nil { setGameMode(enabled: false) }
        armSystemProxyWhenReady = true
        setWarp(enabled: true)
        setLocalProxy(enabled: true)
        if warpState == .running { applySystemProxyWhenReady() }
    }

    private func applySystemProxyWhenReady() {
        guard armSystemProxyWhenReady, warpState == .running,
              case .listening = proxyState else { return }
        armSystemProxyWhenReady = false
        applySystemProxy(true)
    }

    private func applySystemProxy(_ on: Bool) {
        guard on || systemProxyEnabled else { return }   // nothing to undo
        do {
            try SystemProxy.set(enabled: on, port: options.localProxyPort)
            systemProxyEnabled = on
        } catch {
            systemProxyEnabled = SystemProxy.isEnabled(port: options.localProxyPort)
            systemProxyError = error.localizedDescription
        }
    }

    /// Leaving the system pointed at a proxy that died with the app would take
    /// the Mac offline, so the setting is undone on the way out.
    public func restoreSystemProxyOnQuit() {
        guard systemProxyEnabled else { return }
        applySystemProxy(false)
    }

    // MARK: Gaming mode

    @Published public internal(set) var gameState: GameModeController.State = .stopped
    @Published public var gameDisguise: GameModeController.Disguise = .standby
    private var game: GameModeController?

    public var gameStatusText: String? {
        switch gameState {
        case .stopped:  return nil
        case .starting: return "Gaming mode starting - this needs your admin password"
        case .running:  return "Gaming mode on: the whole Mac, games included, goes through WARP"
        case .failed(let why): return why
        }
    }

    /// Gaming mode routes the entire Mac at the IP layer, so it cannot coexist
    /// with the proxy modes that claim the same traffic: turning it on takes
    /// the system proxy, WARP and Tor down first, and turning it off leaves
    /// them off rather than silently restoring a state the user did not pick.
    public func setGameMode(enabled: Bool) {
        guard enabled else {
            game?.stop()
            game = nil
            gameState = .stopped
            return
        }

        armSystemProxyWhenReady = false
        applySystemProxy(false)
        setLocalProxy(enabled: false)
        if options.warpEnabled { setWarp(enabled: false) }
        if options.torEnabled { setTor(enabled: false) }

        guard let controller = GameModeController.bundled() else {
            gameState = .failed("This build has no bundled usque. Build it and run `make bundle-tor`.")
            return
        }
        game = controller
        let disguise = gameDisguise
        controller.start(disguise: disguise) { [weak self] st in
            Task { @MainActor in self?.gameState = st }
        }
    }

    /// Gaming mode owns the routing table; leaving it set after the app quits
    /// would point the Mac at a tunnel that no longer exists.
    public func stopGameModeOnQuit() {
        guard game != nil else { return }
        setGameMode(enabled: false)
    }

    /// WARP and Tor both want to be the proxy's SOCKS upstream; only one can be.
    public func setWarp(enabled: Bool) {
        if enabled, game != nil { setGameMode(enabled: false) }
        if enabled, options.torEnabled { setTor(enabled: false) }
        var o = options
        o.warpEnabled = enabled
        apply(options: o)
        warp?.stop()
        warp = nil
        warpState = .stopped
        guard enabled else { syncProxyUpstream(); return }
        guard let controller = WarpController(socksPort: options.warpSocksPort,
                                              sni: options.warpSNI) else {
            warpState = .failed("This build has no bundled usque. Build it and run `make bundle-tor`.")
            return
        }
        warp = controller
        controller.start { [weak self] st in
            Task { @MainActor in
                self?.warpState = st
                self?.syncProxyUpstream()
                self?.applySystemProxyWhenReady()
            }
        }
    }

    public func setTor(enabled: Bool) {
        if enabled, options.warpEnabled { setWarp(enabled: false) }
        var o = options
        o.torEnabled = enabled
        apply(options: o)
        guard enabled else {
            tor?.stop()
            tor = nil
            torState = .stopped
            syncProxyUpstream()
            return
        }
        guard let controller = TorController() else {
            torState = .failed("This build has no bundled Tor. Run `make bundle-tor`.")
            return
        }
        tor = controller
        controller.start(userBridges: options.torBridges) { [weak self] st in
            Task { @MainActor in
                self?.torState = st
                // The proxy's upstream depends on whether Tor is actually ready;
                // pointing at a half-bootstrapped Tor would fail every connection.
                self?.syncProxyUpstream()
            }
        }
    }

    public func setLocalProxy(enabled: Bool) {
        var o = options
        o.localProxyEnabled = enabled
        apply(options: o)
        guard enabled else {
            proxy?.stop()
            proxy = nil
            proxyState = .stopped
            return
        }
        // Reuse the running proxy: a second LocalProxy on the same port could
        // never bind while the first still held it ("Address already in use").
        if proxy == nil {
            guard let listener = LocalProxy(port: options.localProxyPort,
                                            upstream: currentUpstream()) else {
                proxyState = .failed("Port \(options.localProxyPort) is not usable.")
                return
            }
            proxy = listener
        }
        syncProxyUpstream()
    }

    /// What the proxy is actually pointed at, for the line under the toggle.
    /// It used to say "VPN" whenever Tor was off, which is wrong the moment the
    /// Worker is the upstream — and wrong in the one place someone reads it.
    public var proxyUpstreamLabel: String {
        switch currentUpstream() {
        case .direct: return "VPN"
        case .socks5: return options.warpEnabled ? "WARP" : "Tor"
        case .worker: return "Worker"
        }
    }

    public func setProxyThroughWorker(_ on: Bool) {
        var o = options
        o.proxyThroughWorker = on
        apply(options: o)
        syncProxyUpstream()
    }

    func currentUpstream() -> LocalProxy.Upstream {
        // Deliberately not gated on `warpState == .running`: while WARP is
        // starting, restarting after a wedged tunnel, or failed, the port is
        // simply not listening and dials are refused. Falling back to .direct
        // there would push traffic the user asked to route through WARP straight
        // out to the ISP — a leak, and the harder kind to notice because it works.
        if options.warpEnabled {
            return .socks5(host: "127.0.0.1", port: options.warpSocksPort)
        }
        if options.torEnabled, torState == .running, let port = tor?.socksPort {
            return .socks5(host: "127.0.0.1", port: port)
        }
        if options.proxyThroughWorker {
            let settings = RelayTunnelSettings.load(appGroup: appGroup)
            if settings.enabled, !settings.token.isEmpty {
                return .worker(settings)
            }
        }
        return .direct
    }

    private func syncProxyUpstream() {
        guard options.localProxyEnabled, let proxy else { return }
        proxy.start(upstream: currentUpstream()) { [weak self] st in
            // Same handler as the first start: this one replaces it, and
            // dropping applySystemProxyWhenReady left the system proxy unarmed.
            Task { @MainActor in
                self?.proxyState = st
                self?.applySystemProxyWhenReady()
            }
        }
    }
    #endif
    #if os(iOS)
    // MARK: - WARP (iOS)
    //
    // The same WARP as macOS, but as its own packet tunnel: iOS has neither child
    // processes nor a system SOCKS proxy. `systemProxyEnabled` keeps the macOS
    // name so the home panel and setup guide are shared; here it means "this
    // device is routed through WARP".

    @Published public internal(set) var warpState: WarpController.State = .stopped
    private lazy var warp = WarpController(sni: options.warpSNI)

    @Published public internal(set) var warpRegistered = WarpRegistration.isRegistered()
    @Published public private(set) var warpSetupBusy = false
    @Published public var warpSetupError: String?

    public func registerWarp(licenseKey: String, teamToken: String) async {
        warpSetupBusy = true
        warpSetupError = nil
        defer { warpSetupBusy = false }
        do {
            try await WarpRegistration.register(licenseKey: licenseKey, teamToken: teamToken)
        } catch {
            warpSetupError = error.localizedDescription
        }
        warpRegistered = WarpRegistration.isRegistered()
        if warpRegistered, warpSetupError == nil {
            completeOnboarding()
        }
    }

    public var warpStatusText: String? {
        switch warpState {
        case .stopped: return nil
        case .starting: return "Connecting to WARP… (SNI \(options.warpSNI))"
        case .running: return "All traffic goes through Cloudflare WARP (SNI \(options.warpSNI))"
        case .failed(let why): return why
        }
    }

    /// The iOS app ships as the WARP build (SweepProxyOnly in Info.plist).
    public let proxyOnly = Bundle.main.object(forInfoDictionaryKey: "SweepProxyOnly") as? String == "YES"

    public var systemProxyEnabled: Bool { warpState == .running || warpState == .starting }
    @Published public private(set) var systemProxyError: String?

    public func setEverythingThroughWarp(_ on: Bool) { setWarp(enabled: on) }

    /// Gaming mode on iOS is only about flow rotation.
    ///
    /// The packet tunnel already carries every packet, UDP included, so games
    /// work in the ordinary mode; the warm standby is always on. Rotation is
    /// the one extra step, and it stays opt-in because the swap can briefly
    /// stall new connections.
    @Published public var gameModeEnabled = false {
        didSet {
            guard gameModeEnabled != oldValue else { return }
            if options.warpEnabled { setWarp(enabled: true) }   // restart with the new setting
        }
    }

    public var gameStatusText: String? {
        gameModeEnabled
            ? "Flows are retired before the network can drop them. New connections may pause briefly."
            : nil
    }

    public func setWarp(enabled: Bool) {
        systemProxyError = nil
        var o = options
        o.warpEnabled = enabled
        options = o
        guard enabled else { warp.stop(); return }
        if warp.sni != options.warpSNI { warp = WarpController(sni: options.warpSNI) }
        warp.flowTTLSeconds = gameModeEnabled ? 45 : 0
        warp.start { [weak self] st in Task { @MainActor in self?.warpState = st } }
    }

    /// The tunnel outlives the app; pick its state back up on launch.
    public func attachWarp() {
        warp.attach { [weak self] st in Task { @MainActor in self?.warpState = st } }
    }
    #endif
    /// No verified, unexpired signed bundle => the app has nothing it is allowed
    /// to connect to, and says so instead of implying it is standing guard.
    @Published public private(set) var hasVerifiedConfig = false
    /// Why there is no config: `.notConfigured` (never set up) reads very
    /// differently to the user than `.configurationInvalid` (a bad signature),
    /// so the two must not share one alarming screen.
    @Published public private(set) var configFailureKind: TunnelErrorKind = .notConfigured

    /// Whether pressing the button could plausibly start a tunnel.
    ///
    /// macOS is never a dead end without a signed bundle: `ensureConnectable()`
    /// fetches, probes and pins a public VPN Gate relay on demand, and reports
    /// its own failure if even that fails. Gating on `hasVerifiedConfig` — which
    /// no shipping build ever sets, because `Config/` carries no bundle — made
    /// "How to finish setup" the only reachable action. `.connect` was never
    /// dispatched, so `install()` never ran, so no profile ever existed to
    /// un-gate the button. The relay path and the Worker bypass behind it were
    /// unreachable code.
    private var canAttemptConnection: Bool {
        #if os(macOS)
        return true
        #else
        return hasVerifiedConfig
        #endif
    }


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

    /// App group shared with the extension. `AppConfig` owns the real value but
    /// lives in the app targets, which this package cannot import, so the app
    /// passes it in.
    private let appGroup: String

    public init(configurator: VPNConfigurator, appGroup: String = AppGroupID.resolved) {
        self.configurator = configurator
        self.appGroup = appGroup
        self.presentation = Presentation.make(state: .disconnected, serverName: nil,
                                              killSwitchArmed: true, onDemandArmed: true, quality: nil)
        #if os(macOS)
        // The proxy cannot work without a WARP registration, so the setup guide
        // keeps coming back until one exists, whatever was dismissed before.
        if !warpRegistered { activeSheet = .onboarding }
        #else
        if proxyOnly ? !warpRegistered : !UserDefaults.standard.bool(forKey: "sweep.onboarded") {
            activeSheet = .onboarding
        }
        #endif
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
        // Scope the observation to *our* connection. With `object: nil` every VPN
        // on the machine — including unrelated ones — drove this refresh, which is
        // how an unrelated tunnel ended up rendering as "Protected".
        Task { [weak self] in
            guard let self else { return }
            _ = try? await self.configurator.loadManager()
            NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange,
                                                   object: self.configurator.ourConnection,
                                                   queue: .main) { [weak self] _ in
                Task { @MainActor in await self?.refresh() }
            }
        }
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    public func onDisappear() { pollTask?.cancel(); pollTask = nil; stopWatchingLog() }

    /// Follows the journal while the log screen is open. One second, because the
    /// thing being watched is a connect that can stall for tens of seconds and
    /// the user needs to see which step it stopped on as it stops.
    public func startWatchingLog() {
        logTask?.cancel()
        logTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let entries = self.log.entries()
                await MainActor.run { self.logEntries = entries }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    public func stopWatchingLog() { logTask?.cancel(); logTask = nil }

    public func clearLog() {
        log.clear()
        logEntries = []
        log.record(phase: "connect", kind: "logCleared", detail: "by the user")
    }

    public func copyLog() {
        let text = log.export()
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }

    /// Remembering that the primer was shown is the only thing this app stores
    /// outside the Keychain — it is not a secret and not user data.
    public func completeOnboarding() {
        UserDefaults.standard.set(true, forKey: "sweep.onboarded")
        if activeSheet == .onboarding { activeSheet = nil }
    }

    /// The extension's own account of why the last start failed.
    ///
    /// Read from the shared group rather than asked over IPC, because a tunnel
    /// that dies during startup cannot answer IPC — which is precisely when the
    /// reason is worth having. Nil once a connect succeeds.
    @Published public private(set) var tunnelFailure: TunnelFailure?

    /// When the user last asked for a connection. A failure older than this
    /// belongs to a previous attempt and must not be shown against this one.
    private var connectStartedAt = Date.distantPast
    private var backoffStore: StartBackoffStore { StartBackoffStore(appGroup: appGroup) }

    private func readTunnelFailure() {
        let failure = TunnelFailureStore(appGroup: appGroup).load()
        tunnelFailure = failure
        // The extension is the authority on why it would not start; the UI's
        // generic wording for the kind is a fallback, not a replacement.
        if let failure, !failure.detail.isEmpty { lastError = failure.detail }
    }

    public func refresh() async {
        readTunnelFailure()
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
            onDemandArmed = configurator.profileOnDemandEnabled
            pqHybridActive = s.pqHybridActive
            handshakeAgeSeconds = s.handshakeAgeSeconds
            bytesSent = s.bytesSent
            bytesReceived = s.bytesReceived
            noteRungChange(to: s.rung, connected: s.state.forwardingAllowed)
            rung = s.rung
            quality = s.rttMs.map { Presentation.Quality.from(rttMs: $0, lossFraction: 0) }
            recompute()
        }
    }

    /// Fallback used only when the provider did not answer over IPC.
    ///
    /// `configurator.connectionStatus` is now guaranteed to describe *our* profile
    /// or nothing at all, so it is safe to render — but it carries no rung and no
    /// server name, and we must not invent either.
    private func applySystemStatus() {
        // No Sweep profile in system preferences yet. That is the ordinary
        // first-run state, NOT an error: `install()` is what creates the profile,
        // and creating it is exactly what makes macOS show the approval prompt.
        // Reporting .notConfigured here made the button "How to finish setup",
        // which opens System Settings — so the prompt could never be reached.
        // The only real "not configured" case is having no verified server list.
        guard configurator.hasInstalledProfile else {
            state = canAttemptConnection ? .disconnected : .error(configFailureKind)
            rung = nil
            recompute()
            return
        }
        switch configurator.connectionStatus {
        case .connected:
            // Up, but unattributed until IPC confirms. See TunnelState.verifying.
            state = .verifying
            rung = nil
        case .connecting, .reasserting:
            // The system reports `.connecting` for as long as on-demand keeps
            // restarting a tunnel that cannot come up, so trusting it alone
            // showed a spinner that never ended and never said why. The
            // extension has already written the reason; if that reason is
            // newer than the attempt we are watching, this "connecting" is the
            // next lap of a failing loop, not progress.
            if let failure = tunnelFailure, failure.at > connectStartedAt,
               backoffStore.load().effective().looksPersistentlyBroken {
                state = .error(TunnelErrorKind(rawValue: failure.kind) ?? .allRungsFailed)
            } else {
                state = .reconnecting(attempt: 0)
            }
            rung = nil
        case .disconnecting:
            state = .reconnecting(attempt: 0)
        case .invalid:
            state = .error(.systemDenied)
        default:
            // `.disconnected`. On-demand only counts as armed if the profile
            // actually carries an on-demand rule; the local toggle alone showed
            // "Standing by" with nothing armed behind it.
            if !canAttemptConnection { state = .error(configFailureKind) }
            onDemandArmed = configurator.profileOnDemandEnabled
            if onDemandArmed { state = .onDemandArmed } else { state = .disconnected }
        }
        recompute()
    }

    /// Raise a short-lived banner when the live transport changes under a
    /// connected tunnel. Only a real switch between two known rungs counts —
    /// the first rung after connecting, or losing the rung on disconnect, is
    /// not a "switch".
    private func noteRungChange(to newRung: ProtocolRung?, connected: Bool) {
        defer { lastSeenRung = connected ? newRung : nil }
        guard connected, let newRung, let old = lastSeenRung, old != newRung else { return }
        protocolSwitchNote = "Switched to \(newRung.displayName) — the previous route stopped getting through."
        protocolNoteClearTask?.cancel()
        protocolNoteClearTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(6))
            await MainActor.run { self?.protocolSwitchNote = nil }
        }
    }

    /// Last state written to the journal, so a 5-second poll that finds nothing
    /// changed does not write a line every 5 seconds.
    private var lastLoggedState: TunnelState?

    private func recompute() {
        // Every transition the user-facing screen makes, in one place. This is
        // what turns "it just says connecting" into a timestamped sequence: the
        // absence of a further line after `connecting` is itself the finding.
        if state != lastLoggedState {
            log.record(phase: "state", level: state.isFailure ? .error : .info,
                       kind: "state", detail: "\(lastLoggedState.map(\.logLabel) ?? "—") → \(state.logLabel)")
            lastLoggedState = state
        }
        presentation = Presentation.make(state: state, serverName: serverName,
                                         killSwitchArmed: killSwitchArmed,
                                         onDemandArmed: onDemandArmed, quality: quality)
    }

    /// The in-flight connect, so Cancel can actually interrupt it.
    ///
    /// Without this, Cancel could only ask the OS to stop a tunnel that had not
    /// been started yet — the slow part of a connect is `ensureConnectable()`,
    /// which happens entirely before `start()`. Pressing Cancel during those
    /// seconds did nothing at all.
    private var connectTask: Task<Void, Never>?

    public func perform(_ action: Presentation.Action) {
        switch action {
        case .connect, .retry:
            // Move to `.connecting` on the user's intent, not on the OS
            // reporting it. The OS does not report `.connecting` until
            // `start()` is called, which is after the relay probe — so for the
            // whole probe the screen still said "Connect" while the button was
            // disabled, and there was no way to back out. This is optimistic and
            // `refresh()` overwrites it with the truth moments later.
            // The rung carried here is the one the user forced, or the first the
            // ladder is permitted to try — it is never rendered for
            // `.connecting` (the screen says "Finding the best route"), and
            // `rung`, which *is* rendered, stays nil until the extension
            // reports what it actually negotiated.
            state = .connecting(rung: forcedRung ?? .openVPNTCP)
            recompute()
            connectTask = Task { await run(action) }
        case .cancel, .disconnect:
            // Interrupt the attempt first, then tell the OS. Order matters: if
            // the connect task is still in `ensureConnectable()` it would
            // otherwise go on to install a profile and start a tunnel the user
            // has just asked to abandon.
            connectTask?.cancel()
            connectTask = nil
            Task { await run(action) }
        case .openSettings:
            Task { await run(action) }
        }
    }

    private func run(_ action: Presentation.Action) async {
        isBusy = true
        defer { isBusy = false }
        do {
            switch action {
            case .connect, .retry:
                log.beginRun(action == .retry ? "user pressed Retry" : "user pressed Connect")
                log.record(phase: "connect", kind: "preflight",
                           detail: "servers=\(servers.count) relays=\(relays.count)")
                // Installing an on-demand profile with nothing to connect to is
                // what produces the connect/disconnect loop: the extension
                // throws `noServers`, on-demand restarts it, and it throws
                // again — with the blackhole route installed the whole time.
                guard await ensureConnectable() else {
                    log.record(phase: "connect", level: .error, kind: "preflightFailed",
                               detail: lastError ?? "nothing to connect to")
                    state = .disconnected
                    recompute()
                    return
                }
                guard !Task.isCancelled else { return await abandonConnect() }
                // A new attempt: the previous reason is history, and the streak
                // must not make the first lap of this one look broken.
                connectStartedAt = Date()
                TunnelFailureStore(appGroup: appGroup).clear()
                backoffStore.save(StartBackoff())
                tunnelFailure = nil
                log.record(phase: "profile", kind: "installing",
                           detail: "server=\(serverName ?? "Sweep VPN")")
                try await configurator.install(policy: SecurityPolicy(options: options),
                                               serverDescription: serverName ?? "Sweep VPN")
                log.record(phase: "profile", kind: "installed")
                guard !Task.isCancelled else { return await abandonConnect() }
                log.record(phase: "tunnel", kind: "startRequested")
                try await configurator.start()
                log.record(phase: "tunnel", kind: "startReturned",
                           detail: "handed to the extension; waiting on it to report")
            case .disconnect, .cancel:
                log.record(phase: "connect", level: .warn, kind: "userStopped",
                           detail: action == .cancel ? "Cancel" : "Disconnect")
                // Explicit user action: disarm on-demand so the OS does not
                // immediately restart the tunnel (the connect/disconnect loop).
                try await configurator.stop(userInitiated: true)
                log.record(phase: "tunnel", kind: "stopRequested")
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
            log.record(phase: "connect", level: .error, kind: "actionThrew",
                       detail: "\(action.rawValue): \(error)")
            lastError = error.localizedDescription
            await refresh()
        }
    }

    /// Cancel landed while the connect was still in its pre-flight, before any
    /// profile was installed. Nothing to stop at the OS level — just put the
    /// screen back where the user left it.
    private func abandonConnect() async {
        log.record(phase: "connect", level: .warn, kind: "cancelled",
                   detail: "abandoned before the tunnel was started")
        await refresh()
    }

    /// Guarantees the extension will have something to connect to, picking a
    /// public relay if that is the only option available.
    ///
    /// Returns false when nothing could be found, in which case the caller must
    /// not start the tunnel — the relay picker is opened instead.
    private func ensureConnectable() async -> Bool {
        #if os(macOS)
        // The relay check comes first on macOS, deliberately.
        //
        // `hasVerifiedConfig` becomes true as soon as the extension answers with
        // a server list — including a stale one it cached from an earlier
        // session. Returning early on it meant that with no relay pinned the
        // extension raced the WireGuard ladder against servers that answer
        // nothing here, reported allRungsFailed, and the OpenVPN-over-Worker
        // route — the only one that survives this gateway — was never tried.
        let store = RelaySelectionStore(appGroup: appGroup)
        let pinned = store.load()
        #else
        if hasVerifiedConfig { return true }
        #endif
        #if os(macOS)

        if relays.isEmpty { loadCachedRelays() }
        // Refresh a list that is merely old, not only one that is missing.
        // VPN Gate rows are volunteers' machines that come and go within hours,
        // and both the pin below and its replacement are drawn from this list.
        // Re-pinning from a stale list just picks the next relay that is also
        // gone.
        if relays.isEmpty || (relaysFetchedAt.map { Date().timeIntervalSince($0) > 3600 } ?? true) {
            await refreshRelays()
        }

        // A pin is only good while the relay is still on the list.
        //
        // Nothing revalidated it before, so a relay chosen once was dialled
        // forever. That fails in a way that names nothing: the Worker builds its
        // egress allow-list from this same list, answers a delisted host with
        // `0x00 not a known relay`, and all the extension sees is a connection
        // that never carries a byte. Measured against the deployed Worker: the
        // pinned 219.100.37.196 was refused, and it is absent from the live CSV.
        if let pinned {
            let live = Set(relays.flatMap { $0.endpoints.map(\.host) })
            if pinned.endpoints.contains(where: { live.contains($0.host) }) {
                // A pin saved before pools existed — or one whose alternates
                // have since been delisted — leaves the extension with nothing
                // to fail over to, which is the whole failure this pool exists
                // to prevent. Top it up before connecting rather than after the
                // relay drops.
                let pool = store.loadAll().filter { relay in
                    relay.endpoints.contains { live.contains($0.host) }
                }
                if pool.count < 2 {
                    await probeRelays(limit: 40)
                    store.saveAll(relayPool(headedBy: pinned))
                    log.record(phase: "relay", level: .info, kind: "relayPoolTopUp",
                               detail: "\(store.loadAll().count) relays available for handover")
                } else if pool.count < store.loadAll().count {
                    store.saveAll(pool)   // drop the delisted alternates
                }
                return true
            }
            log.record(phase: "relay", level: .warn, kind: "pinnedRelayDelisted",
                       detail: "\(pinned.name) is no longer on the list — reselecting")
            store.clear()
        }
        guard !relays.isEmpty else {
            // `refreshRelays` has already put the specific reason (a 403 block
            // page reads very differently from being offline) into relayStatus.
            lastError = relayStatus ?? "No relays available yet."
            activeSheet = .publicRelays
            return false
        }

        // Measure before pinning: VPN Gate's advertised score says nothing about
        // reachability from here, and pinning a dead relay just moves the same
        // failure into the extension.
        await probeRelays(limit: 40)
        let reachable = rankedRelays.first { ($0.1?.lossFraction ?? 1) < 1 }?.0
        guard let chosen = reachable ?? rankedRelays.first?.0 else {
            lastError = "No relay answered. Pick one manually or try again."
            activeSheet = .publicRelays
            return false
        }
        select(server: chosen)
        return true
        #else
        lastError = "No verified configuration to connect to."
        return false
        #endif
    }

    public func apply(options newOptions: SecurityPolicyOptions) {
        let profileChanged = SecurityPolicy.profileInputs(options)
            != SecurityPolicy.profileInputs(newOptions)
        options = newOptions
        Task {
            _ = try? await configurator.send(.setSecurityOptions(newOptions))
            // The provider always hears about the change. The profile is only
            // rewritten when the profile itself would differ — saving it with
            // the kill switch on re-arms on-demand and connects the tunnel, so
            // an app-local setting must not go anywhere near it.
            if profileChanged {
                try? await configurator.install(policy: SecurityPolicy(options: newOptions),
                                                serverDescription: serverName ?? "Sweep VPN")
            }
            await refresh()
        }
    }

    /// Modes a user can pick directly; `forced` is set from the Advanced picker.
    public static let selectableModes: [ProtocolPreference] = [.automatic, .fast]

    /// Rungs this build can run *and* has somewhere to run to, in ladder order.
    ///
    /// A rung with no endpoint in the current inventory is not a choice, it is a
    /// dead end: every WireGuard and Shadowsocks rung needs a server whose key
    /// this build holds, and no signed bundle ships one. Offering them promised
    /// fallbacks that could never engage. Driving this from the inventory rather
    /// than a hard-coded list means it widens again on its own the day `Config/`
    /// carries real servers.
    public var selectableRungs: [ProtocolRung] {
        let reachable = Set((servers + relays).flatMap { $0.endpoints.map(\.rung) })
        return ProtocolRung.allCases.filter {
            AdapterFactory.availableRungs.contains($0) && reachable.contains($0)
        }
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

    // MARK: - Public relays

    /// Relays ordered the way the user asked for: fastest measured first, then
    /// everything unmeasured. Reuses `ServerCatalog` so relays are scored by
    /// exactly the same rules as our own servers.
    ///
    /// TCP relays only. They are reached through the Worker tunnel, whose
    /// `connect()` is a TCP socket, so a UDP relay has nothing to travel over —
    /// and on this network a direct UDP relay is dead anyway. The relay's own
    /// port no longer matters: the gateway sees a WSS session to Cloudflare and
    /// never learns which port the Worker dialled, so this is not narrowed to
    /// 443 and keeps most of the list rather than a handful of it.
    public var rankedRelays: [(Server, ServerProbe?)] {
        let tcpOnly = relays.filter { $0.supports(.openVPNTCP) }
        return ServerCatalog(servers: tcpOnly, probes: relayProbes,
                             rungs: [.openVPNTCP]).ranked()
    }

    /// Countries present in the fetched list, for the picker's filter.
    public var relayCountries: [String] {
        Array(Set(relays.map(\.countryCode))).sorted()
    }

    public func loadCachedRelays() {
        let fetcher = VPNGateFetcher(customSource: customRelaySource())
        guard let cache = fetcher.cache() else { return }
        relays = cache.servers
        relaysFetchedAt = cache.fetchedAt
    }

    private func customRelaySource() -> URL? {
        let trimmed = relaySourceURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return URL(string: trimmed)
    }

    public func refreshRelays() async {
        guard !isRefreshingRelays else { return }
        isRefreshingRelays = true
        relayStatus = nil
        UserDefaults.standard.set(relaySourceURL, forKey: "sweep.relaySource")
        defer { isRefreshingRelays = false }

        let fetcher = VPNGateFetcher(customSource: customRelaySource())
        log.record(phase: "relay", kind: "fetchingList",
                   detail: customRelaySource() == nil ? "default sources" : "custom mirror")
        do {
            let fetched = try await fetcher.refresh()
            relays = fetched
            log.record(phase: "relay", kind: "listFetched", detail: "\(fetched.count) relays")
            relaysFetchedAt = fetcher.cache()?.fetchedAt ?? Date()
            relayStatus = "\(fetched.count) relays in \(Set(fetched.map(\.countryCode)).count) countries"
        } catch VPNGateFetcher.FetchError.allSourcesFailed(let status) {
            // Naming the block page explicitly, because "couldn't connect" sends
            // the user looking for the wrong problem.
            relayStatus = status == 403
                ? "Blocked on this network (HTTP 403). Set a mirror URL below and try again."
                : "Could not reach the VPN Gate list. Set a mirror URL below and try again."
            log.record(phase: "relay", level: .error, kind: "listFetchFailed",
                       detail: "all sources failed, last status \(status.map(String.init) ?? "none")")
        } catch {
            relayStatus = "Could not read the relay list: \(error)"
            log.record(phase: "relay", level: .error, kind: "listFetchFailed", detail: "\(error)")
        }
    }

    /// Measure every relay so "fastest" means measured-fastest rather than
    /// advertised-fastest. The probe is a connect to the relay's own port —
    /// nothing is sent to any third-party latency service.
    public func probeRelays(limit: Int = 80) async {
        guard !isProbingRelays, !relays.isEmpty else { return }
        isProbingRelays = true
        defer { isProbingRelays = false }

        // Probing several hundred hosts at once is what makes a network stack
        // start dropping connections and report healthy servers as dead, so
        // this takes the most promising slice rather than the whole list.
        let targets = Array(rankedRelays.map(\.0).prefix(limit))
        // The single longest step in a connect, and previously the most silent:
        // the screen showed a disabled "Connect" for however long this took.
        let started = Date()
        log.record(phase: "relay", kind: "probing", detail: "\(targets.count) relays, 2s timeout each")
        let prober = ServerProber(timeout: 2.0, samples: 2)
        let results: [ServerProber.Result] = await withCheckedContinuation { continuation in
            prober.probe(targets, rungs: [.openVPNTCP]) { continuation.resume(returning: $0) }
        }
        for result in results { relayProbes[result.id] = result.probe }
        let reachable = results.filter { $0.probe.lossFraction < 1 }.count
        relayStatus = "Measured \(results.count) relays — \(reachable) answered"
        log.record(phase: "relay", level: reachable == 0 ? .error : .info, kind: "probed",
                   detail: String(format: "%d of %d answered in %.1fs",
                                  reachable, results.count, Date().timeIntervalSince(started)))
    }

    public let automaticID: ServerID = "__automatic__"

    public var isAutomaticSelected: Bool { selectedServerID == nil || selectedServerID == automaticID }

    /// Drop back to our own servers, clearing any pinned relay.
    public func clearRelaySelection() {
        #if os(macOS)
        RelaySelectionStore(appGroup: appGroup).clear()
        Task { _ = try? await configurator.send(.relaySelectionChanged) }
        #endif
    }

    public func selectAutomatic() {
        clearRelaySelection()
        selectedServerID = automaticID
        serverName = catalog.fastest(includeAccountRequired: showAccountOnlyServers)?.name
        recompute()
        Task { _ = try? await configurator.send(.reconnect) }
    }

    public func select(server: Server) {
        selectedServerID = server.id
        serverName = server.name
        recompute()

        // A public relay is not in the provider's signed catalog and never will
        // be, so it is handed over through the shared store instead — which is
        // also what lets it survive the extension being restarted.
        guard server.isThirdPartyRelay else {
            Task { _ = try? await configurator.send(.selectServer(server.id)) }
            return
        }
        #if os(macOS)
        RelaySelectionStore(appGroup: appGroup).saveAll(relayPool(headedBy: server))
        Task { _ = try? await configurator.send(.relaySelectionChanged) }
        #else
        lastError = "Public relays need the OpenVPN rung, which this build only has on macOS."
        #endif
    }

    #if os(macOS)
    /// The chosen relay first, then the best measured alternates.
    ///
    /// The extension can only fail over to relays it was given, and a VPN Gate
    /// relay drops sessions on its own schedule, so handing it one relay is
    /// handing it a tunnel with a fixed lifetime.
    private func relayPool(headedBy head: Server) -> [Server] {
        let alternates = rankedRelays
            .filter { ($0.1?.lossFraction ?? 1) < 1 }
            .map(\.0)
            .filter { $0.id != head.id }
        return [head] + alternates.prefix(Self.relayPoolSize - 1)
    }

    /// Sized from measured relay lifetimes, not from taste: soaking three
    /// relays through the Worker, the longest single session lasted 9.5 min,
    /// one dropped at 92 s and one never connected at all. An hour therefore
    /// costs somewhere between six and thirty handovers, so the pool has to be
    /// deep enough to spend that many dials without running dry.
    private static let relayPoolSize = 16
    #endif

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
