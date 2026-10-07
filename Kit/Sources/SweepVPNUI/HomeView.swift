import SwiftUI
#if os(iOS)
import UIKit
#endif
import SweepVPNCore

/// The five-fact home screen: protected state, server, quality, security glyph,
/// one primary control. Everything else lives behind the gear.
public struct HomeView: View {
    @ObservedObject public var model: VPNViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    #if os(macOS)
    @Environment(\.controlActiveState) private var controlActive
    private var windowInFront: Bool { controlActive != .inactive }
    #else
    private let windowInFront = true
    #endif

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        ZStack {
            Backdrop(tint: model.presentation.tint,
                     animate: !reduceMotion && model.animateBackdrop && windowInFront)
            VStack(spacing: 20) {
                header
                #if os(macOS)
                if model.availableUpdate != nil { UpdateBanner(model: model) }
                #endif
                Spacer(minLength: 0)
                if model.proxyOnly {
                    ProxyHomePanel(model: model)
                    Spacer(minLength: 0)
                } else {
                    vpnBody
                }
            }
            .padding(24)
        }
        .sheet(item: $model.activeSheet) { sheet in
            switch sheet {
            case .settings:     SettingsView(model: model)
            case .serverPicker: ServerPickerView(model: model)
            case .publicRelays: PublicRelayPickerView(model: model)
            case .setupGuide:   SetupGuideView(model: model)
            case .onboarding:   OnboardingView(model: model).interactiveDismissDisabled()
            case .connectionLog: ConnectionLogView(model: model)
            }
        }
    }

    @ViewBuilder private var vpnBody: some View {
        statusPanel
        serverPill
        Spacer(minLength: 0)
        if let note = model.protocolSwitchNote { protocolSwitchRow(note) }
        if let error = model.lastError { errorRow(error) }
        primaryButton
    }

    /// The gear lives in the layout, not in `.toolbar`: a toolbar item is
    /// silently dropped by scenes that have no toolbar, which is how this
    /// button went missing entirely.
    private var header: some View {
        HStack {
            Text("Sweep VPN").font(.headline)
            Spacer()
            // The connection log is one step further in, under Settings ▸
            // Diagnostics. It is always there, never hung off an error banner:
            // a connect that hangs in "Connecting…" raises no banner at all.
            Button { model.activeSheet = .settings } label: {
                Image(systemName: "gearshape").font(.title3)
                    .frame(width: 32, height: 32).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Settings")
            .accessibilityLabel("Settings")
        }
    }

    /// A failed Connect/Retry used to set `lastError` that nothing rendered, so
    /// the button looked inert. Show it, and let the user dismiss it.
    private func errorRow(_ error: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(error).font(.caption).multilineTextAlignment(.leading)
                // Which attempt produced this, so a stale reason is obvious and
                // a live one says which route was being tried when it broke.
                if let failure = model.tunnelFailure {
                    Text([failure.rung.map { "via \($0)" },
                          failure.at.formatted(date: .omitted, time: .standard)]
                            .compactMap { $0 }.joined(separator: " · "))
                        .font(.caption2).foregroundStyle(.secondary)
                    // The banner names the failure; the log says where in the
                    // connect it happened. One line of summary is not enough to
                    // tell a dead relay from an unreachable Worker.
                    Button("See connection log") { model.activeSheet = .connectionLog }
                        #if os(macOS)
                        .buttonStyle(.link).font(.caption2)
                        #else
                        .buttonStyle(.borderless).font(.caption2)
                        #endif
                }
            }
            Spacer(minLength: 0)
            Button { model.lastError = nil } label: { Image(systemName: "xmark") }
                .buttonStyle(.plain).accessibilityLabel("Dismiss error")
        }
        .padding(12)
        .frame(maxWidth: 420)
        .background(.thinMaterial, in: .rect(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    /// Auto-mode fell back to another transport. Shown briefly so a protocol
    /// switch reads as the app working, not the connection breaking.
    private func protocolSwitchRow(_ note: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(.blue)
            Text(note).font(.caption).multilineTextAlignment(.leading)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: 420)
        .background(.thinMaterial, in: .rect(cornerRadius: 12, style: .continuous))
        .transition(.opacity)
        .accessibilityElement(children: .combine)
    }

    private var statusPanel: some View {
        VStack(spacing: 12) {
            Image(systemName: model.presentation.tint == .good ? "lock.shield.fill" : "shield.slash")
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(model.presentation.tint.color)
            Text(model.presentation.headline)
                .font(.title2.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(model.presentation.detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if model.presentation.showsQuality, let q = model.quality {
                QualityRow(quality: q)
            }
            if let route = model.routeDescription {
                Text(route).font(.caption2).foregroundStyle(.secondary)
                    .accessibilityLabel("Route in use: \(route)")
            }
            SecurityGlyphRow(killSwitchArmed: model.killSwitchArmed,
                             onDemandArmed: model.onDemandArmed,
                             pqActive: model.pqHybridActive)
        }
        .padding(24)
        .frame(maxWidth: 420)
        .background(.ultraThinMaterial, in: .rect(cornerRadius: 24, style: .continuous))
        .shadow(color: .black.opacity(0.12), radius: 18, y: 8)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(model.presentation.voiceOver)
    }

    /// With no signed bundle there is nothing to pick from, but the pill still
    /// has to be reachable — its empty state is where the explanation lives.
    private var pillTitle: String {
        if model.servers.isEmpty { return "No servers configured" }
        return model.isAutomaticSelected ? "Automatic" : (model.serverName ?? "No server selected")
    }

    private var serverPill: some View {
        Button { model.activeSheet = .serverPicker } label: {
            HStack(spacing: 8) {
                Image(systemName: model.servers.isEmpty ? "exclamationmark.circle"
                        : (model.isAutomaticSelected ? "bolt.badge.automatic.fill" : "mappin.and.ellipse"))
                VStack(alignment: .leading, spacing: 1) {
                    Text(pillTitle)
                    if let subtitle = model.serverSubtitle {
                        Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Image(systemName: "chevron.right").font(.caption)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            .background(.thinMaterial, in: Capsule())
        }
        .buttonStyle(.plain)
        .opacity(model.servers.isEmpty ? 0.7 : 1)
        .accessibilityLabel("Server: \(pillTitle). Double tap to change.")
    }

    private var primaryButton: some View {
        Button { model.perform(model.presentation.primaryAction) } label: {
            Text(model.presentation.primaryActionTitle)
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: 50)
        }
        .buttonStyle(.borderedProminent)
        .tint(model.presentation.tint == .good ? .green : .accentColor)
        .controlSize(.large)
        .frame(maxWidth: 420)
        // `isBusy` covers the whole connect, including a relay probe that can
        // run for tens of seconds. Disabling the button for all of it left the
        // user with a dead control and no way out — which is the one moment
        // Cancel has to work. A cancel is never busy-blocked.
        .disabled(model.isBusy && model.presentation.primaryAction != .cancel)
    }
}

/// Home screen of the proxy-only release: WARP state and the one switch that
/// matters, instead of a Connect button whose extension this build lacks.
struct ProxyHomePanel: View {
    @ObservedObject var model: VPNViewModel

    private var headline: String {
        if !model.warpRegistered { return "WARP is not set up" }
        #if os(macOS)
        if model.systemProxyEnabled { return "This Mac is using WARP" }
        #else
        if model.warpState == .running { return "This \(DeviceNoun.current) is using WARP" }
        if model.warpState == .starting { return "Connecting to WARP…" }
        #endif
        if model.options.warpEnabled {
            if model.warpState == .running { return "WARP is ready" }
            return model.warpState.isFailed ? "WARP could not start" : "Starting WARP…"
        }
        return "Proxy is off"
    }

    #if os(macOS)
    private var up: Bool { model.connectionEstablished }

    private var macHeadline: String {
        if !model.warpRegistered { return "WARP is not set up" }
        if model.gameState == .running { return "Connected in gaming mode" }
        if model.systemProxyEnabled { return "Connected" }
        if model.connectionActive { return "Connecting…" }
        if model.gameState.isFailed || model.warpState.isFailed || model.systemProxyError != nil {
            return "Could not connect"
        }
        return "Not connected"
    }

    /// One line under the headline: the failure if there is one, otherwise
    /// what the current mode does.
    private var macDetail: (text: String, isError: Bool) {
        if case .failed(let why) = model.gameState { return (why, true) }
        if let why = model.systemProxyError { return (why, true) }
        if !model.connectionIsGaming, case .failed(let why) = model.warpState { return (why, true) }
        if model.gameState == .starting { return ("macOS will ask for your admin password.", false) }
        if model.gameState == .running { return ("Everything on this Mac goes through WARP, games included.", false) }
        if model.systemProxyEnabled { return ("Apps that use the system proxy go through WARP.", false) }
        if model.connectionActive { return ("Starting WARP…", false) }
        return (model.gamingPreferred
                ? "Gaming routes the whole Mac, so games work too."
                : "Routes apps that use the system proxy.", false)
    }

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: up ? "lock.shield.fill" : "shield")
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(up ? .green : .secondary)
                .accessibilityHidden(true)
            Text(macHeadline).font(.title2.weight(.semibold))
            Text(macDetail.text).font(.caption)
                .foregroundStyle(macDetail.isError ? .red : .secondary)
                .multilineTextAlignment(.center).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if model.warpRegistered {
                HStack(spacing: 10) {
                    Button { model.toggleConnection() } label: {
                        Text(model.connectionActive ? "Disconnect" : "Connect")
                            .font(.headline).frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(model.connectionActive ? .red : .accentColor)
                    .keyboardShortcut(.defaultAction)

                    Toggle(isOn: $model.gamingPreferred) {
                        Label("Gaming", systemImage: "gamecontroller.fill")
                    }
                    .toggleStyle(.switch)
                    .padding(.horizontal, 12)
                    .frame(minHeight: 44)
                    .background(.thinMaterial, in: .rect(cornerRadius: 10, style: .continuous))
                    .disabled(model.connectionActive)
                    .help(model.connectionActive
                          ? "Disconnect to change mode"
                          : "On: Connect routes the whole Mac so games work. Off: Connect uses the system proxy.")
                    .accessibilityHint("Chooses how the next Connect routes traffic")
                }
                .padding(.top, 4)
                if model.connectionActive {
                    Text("Disconnect to change mode.")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            } else {
                Button("Set up WARP") { model.activeSheet = .onboarding }
                    .buttonStyle(.borderedProminent).controlSize(.large)
            }
        }
        .padding(24)
        .frame(maxWidth: 420)
        .background(.ultraThinMaterial, in: .rect(cornerRadius: 24, style: .continuous))
        .animation(.easeOut(duration: 0.2), value: model.connectionActive)
    }
    #else
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: model.systemProxyEnabled ? "lock.shield.fill" : "shield")
                .font(.system(size: 44, weight: .medium))
                .foregroundStyle(model.systemProxyEnabled ? .green : .secondary)
            Text(headline).font(.title2.weight(.semibold))
            if let status = model.warpStatusText {
                Text(status).font(.caption)
                    .foregroundStyle(model.warpState.isFailed ? .red : .secondary)
                    .multilineTextAlignment(.center).textSelection(.enabled)
            }
            if let why = model.systemProxyError {
                Text(why).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
            }
            if model.warpRegistered {
                Button {
                    model.setEverythingThroughWarp(!model.systemProxyEnabled)
                } label: {
                    Text(model.systemProxyEnabled ? "Stop routing this \(DeviceNoun.current) through WARP"
                                                  : "Route this \(DeviceNoun.current) through WARP")
                        .font(.headline).frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.borderedProminent)
                .tint(model.systemProxyEnabled ? .red : .accentColor)
                #if os(macOS)
                Text("macOS asks for your password each way. For a single app, use Settings ▸ Tor and proxy.")
                    .font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
                #else
                Text("iOS asks once to add a VPN configuration. It stays on after you close Sweep; turn it off here or in Settings ▸ VPN.")
                    .font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
                #endif
            } else {
                Button("Set up WARP") { model.activeSheet = .onboarding }
                    .buttonStyle(.borderedProminent).controlSize(.large)
            }
        }
        .padding(24)
        .frame(maxWidth: 420)
        .background(.ultraThinMaterial, in: .rect(cornerRadius: 24, style: .continuous))
    }
    #endif
}

/// "Mac", "iPhone" or "iPad", for copy that names the device being routed.
enum DeviceNoun {
    @MainActor static var current: String {
        #if os(macOS)
        return "Mac"
        #else
        return UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
        #endif
    }
}

/// One slow gradient keyed to state. Motion is gated by Reduce Motion and by
/// power state — an always-animating blurred backdrop is a real battery cost.
struct Backdrop: View {
    let tint: Presentation.Tint
    let animate: Bool
    @State private var phase = false

    /// The tint is a hint, not a wash: the state is already carried by the icon,
    /// the headline and the button. A heavy gradient hurts contrast for the text
    /// sitting on it and costs GPU time on an always-visible surface.
    private var strength: Double { tint == .neutral ? 0.06 : 0.14 }

    var body: some View {
        ZStack {
            Color(nsColorOrSystemBackground)
            LinearGradient(colors: [tint.color.opacity(strength),
                                    Color.clear,
                                    tint.color.opacity(strength * 0.5)],
                           startPoint: phase ? .topLeading : .bottomTrailing,
                           endPoint: phase ? .bottomTrailing : .topLeading)
        }
        .ignoresSafeArea()
        .animation(animate ? .easeInOut(duration: 14).repeatForever(autoreverses: true) : nil,
                   value: phase)
        .onAppear { if animate { phase.toggle() } }
        // A repeatForever animation outlives the flag that started it, so a
        // window sent to the background kept the GPU drawing a gradient nobody
        // could see. Setting the phase without an animation is what stops it.
        .onChange(of: animate) { phase = $0 }
    }

    private var nsColorOrSystemBackground: Color {
        #if os(macOS)
        Color(nsColor: .windowBackgroundColor)
        #else
        Color(uiColor: .systemBackground)
        #endif
    }
}

struct QualityRow: View {
    let quality: Presentation.Quality
    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<3, id: \.self) { i in
                Capsule()
                    .fill(i < bars ? Color.primary.opacity(0.8) : Color.primary.opacity(0.15))
                    .frame(width: 16, height: 6)
            }
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Connection quality: \(label)")
    }
    private var bars: Int { quality == .good ? 3 : quality == .fair ? 2 : 1 }
    private var label: String { quality.rawValue.capitalized }
}

/// Small, honest security row — not a dashboard.
struct SecurityGlyphRow: View {
    let killSwitchArmed: Bool
    let onDemandArmed: Bool
    let pqActive: Bool
    var body: some View {
        HStack(spacing: 14) {
            glyph("lock.fill", "Kill switch", killSwitchArmed)
            glyph("bolt.horizontal.fill", "Auto-connect", onDemandArmed)
            glyph("atom", "Post-quantum", pqActive)
        }
        .font(.caption2)
        .lineLimit(1)
        .minimumScaleFactor(0.8)
        .foregroundStyle(.secondary)
    }
    private func glyph(_ system: String, _ title: String, _ on: Bool) -> some View {
        Label(title, systemImage: on ? system : "\(system.replacingOccurrences(of: ".fill", with: "")).slash")
            .labelStyle(.titleAndIcon)
            .opacity(on ? 1 : 0.45)
            .accessibilityLabel("\(title): \(on ? "on" : "off")")
    }
}

#if os(macOS)
/// The reminder half of the updater: quiet until a newer release exists, then
/// one line with the only two answers there are.
struct UpdateBanner: View {
    @ObservedObject var model: VPNViewModel

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.down.circle.fill").foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text("Version \(model.availableUpdate?.version ?? "") is available")
                    .font(.callout.weight(.medium))
                if case .downloading = model.updateState {
                    Text("Downloading and verifying…").font(.caption).foregroundStyle(.secondary)
                } else if case .failed(let why) = model.updateState {
                    Text(why).font(.caption).foregroundStyle(.red)
                }
            }
            Spacer(minLength: 0)
            Button("Update") { model.installUpdate() }
                .disabled(model.updateState == .downloading)
            Button("Later") { model.snoozeUpdate() }
                .buttonStyle(.plain).font(.callout).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}
#endif
