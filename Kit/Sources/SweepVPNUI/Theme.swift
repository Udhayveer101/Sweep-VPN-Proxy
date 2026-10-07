import SwiftUI

/// The app's one look: true black, dark grey surfaces, system blue for what
/// you can press and green for "protected". macOS only for now; on iOS every
/// token falls back to the system colour it replaces, so shared views keep
/// their existing appearance there.
enum Midnight {
    #if os(macOS)
    static let background = Color.black
    static let card = Color(red: 0.11, green: 0.11, blue: 0.118)       // #1c1c1e
    static let raised = Color(red: 0.173, green: 0.173, blue: 0.18)    // #2c2c2e
    static let accent = Color(red: 0.039, green: 0.518, blue: 1)       // #0a84ff
    static let good = Color(red: 0.188, green: 0.82, blue: 0.345)      // #30d158
    static let danger = Color(red: 1, green: 0.271, blue: 0.227)       // #ff453a
    static let warning = Color(red: 1, green: 0.624, blue: 0.039)      // #ff9f0a
    #else
    static let background = Color(uiColor: .systemBackground)
    static let card = Color(uiColor: .secondarySystemBackground)
    static let raised = Color(uiColor: .tertiarySystemBackground)
    static let accent = Color.accentColor
    static let good = Color.green
    static let danger = Color.red
    static let warning = Color.orange
    #endif
    static let hairline = Color.primary.opacity(0.12)

    /// Chrome behind a row or a banner. A flat card here; iOS keeps the
    /// material it always had.
    static var surface: AnyShapeStyle {
        #if os(macOS)
        AnyShapeStyle(card)
        #else
        AnyShapeStyle(.thinMaterial)
        #endif
    }
    static var panel: AnyShapeStyle {
        #if os(macOS)
        AnyShapeStyle(card)
        #else
        AnyShapeStyle(.ultraThinMaterial)
        #endif
    }
}

extension View {
    /// Root of a window or sheet: black canvas, dark controls, blue tint.
    @ViewBuilder func midnightPage() -> some View {
        #if os(macOS)
        self.background(Midnight.background)
            .tint(Midnight.accent)
            .preferredColorScheme(.dark)
        #else
        self
        #endif
    }

    /// A surface one step above the page.
    func midnightCard(radius: CGFloat = 16, raised: Bool = false) -> some View {
        background(raised ? Midnight.raised : Midnight.card,
                   in: .rect(cornerRadius: radius, style: .continuous))
    }
}

/// The home screen's one control: a round power button whose ring is the
/// connection state. Grey when off, a turning blue arc while starting, green
/// once traffic is carried.
struct PowerOrb: View {
    enum Phase { case off, starting, on }

    let phase: Phase
    let action: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var turning = false

    private var color: Color {
        switch phase {
        case .off: return .secondary
        case .starting: return Midnight.accent
        case .on: return Midnight.good
        }
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle().fill(Midnight.card)
                Circle().strokeBorder(color.opacity(phase == .on ? 1 : 0.3), lineWidth: 4)
                if phase == .starting {
                    // Only drawn while starting, so nothing animates once the
                    // connection is up or down.
                    Circle().inset(by: 2)
                        .trim(from: 0, to: reduceMotion ? 1 : 0.28)
                        .stroke(color, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .rotationEffect(.degrees(turning ? 360 : 0))
                        .animation(reduceMotion ? nil
                                   : .linear(duration: 1.1).repeatForever(autoreverses: false),
                                   value: turning)
                        .onAppear { turning = true }
                        .onDisappear { turning = false }
                }
                Image(systemName: "power")
                    .font(.system(size: 46, weight: .medium))
                    .foregroundStyle(color)
            }
            .frame(width: 136, height: 136)
            .shadow(color: phase == .on ? Midnight.good.opacity(0.35) : .clear, radius: 22)
            .contentShape(Circle())
        }
        .buttonStyle(OrbPressStyle())
        .animation(.easeOut(duration: 0.25), value: phase)
    }
}

private struct OrbPressStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.95 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}
