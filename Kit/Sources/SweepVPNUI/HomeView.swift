import SwiftUI
import SweepVPNCore

/// The five-fact home screen: protected state, server, quality, security glyph,
/// one primary control. Everything else lives behind the gear.
public struct HomeView: View {
    @ObservedObject public var model: VPNViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        ZStack {
            Backdrop(tint: model.presentation.tint, animate: !reduceMotion && model.animateBackdrop)
            VStack(spacing: 20) {
                Spacer(minLength: 0)
                statusPanel
                serverPill
                Spacer(minLength: 0)
                primaryButton
            }
            .padding(24)
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { model.showSettings = true } label: { Image(systemName: "gearshape") }
                    .accessibilityLabel("Settings")
            }
        }
        .sheet(isPresented: $model.showSettings) { SettingsView(model: model) }
        .sheet(isPresented: $model.showOnboarding) {
            OnboardingView(model: model).interactiveDismissDisabled()
        }
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

    private var serverPill: some View {
        Button { model.showServerPicker = true } label: {
            HStack(spacing: 8) {
                Image(systemName: model.isAutomaticSelected ? "bolt.badge.automatic.fill" : "mappin.and.ellipse")
                VStack(alignment: .leading, spacing: 1) {
                    Text(model.isAutomaticSelected ? "Automatic" : (model.serverName ?? "No server selected"))
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
        .accessibilityLabel("Server: \(model.serverName ?? "none selected"). Double tap to change.")
        .sheet(isPresented: $model.showServerPicker) { ServerPickerView(model: model) }
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
        .disabled(model.isBusy)
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
