import SwiftUI
import SweepVPNCore

/// Permission priming: explain what the system dialog is about to ask *before*
/// it appears, because a denied VPN-configuration prompt is hard to recover from
/// (vault 11-UX/Onboarding-And-Permission-Priming). It also states the honest
/// limits up front rather than in a support article.
public struct OnboardingView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        VStack(spacing: 24) {
            Spacer(minLength: 0)
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 48, weight: .medium))
                    .foregroundStyle(.green)
                Text("Sweep VPN").font(.title.weight(.semibold))
                Text("No account, no logs, no third-party SDKs.")
                    .font(.subheadline).foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 16) {
                point("checkmark.shield", "Traffic is blocked when the tunnel is down",
                      "The kill switch fails closed — nothing loads rather than leaking.")
                point("arrow.triangle.branch", "It finds a route that works",
                      "If this network blocks WireGuard, Sweep falls back through QUIC, TLS and Shadowsocks automatically.")
                // Both points are platform-specific: naming iOS on a Mac makes
                // the app look like it does not know where it is running.
                #if os(iOS)
                point("gear.badge", "iOS will ask to add a VPN configuration",
                      "That system prompt is next. Sweep cannot connect without it.")
                point("exclamationmark.triangle", "One honest limit",
                      "On iOS, some traffic to Apple's own services can leave outside the tunnel. No app can change that.")
                #else
                point("gear.badge", "macOS will ask to allow a system extension",
                      "You will approve it once in System Settings. Sweep cannot connect without it.")
                point("exclamationmark.triangle", "A second layer on Mac",
                      "A network filter blocks traffic whenever the tunnel is not carrying it, so a crash cannot open a leak.")
                #endif
            }
            .padding(20)
            .background(.ultraThinMaterial, in: .rect(cornerRadius: 20, style: .continuous))

            Spacer(minLength: 0)

            Button {
                model.completeOnboarding()
                dismiss()
            } label: {
                Text("Continue").font(.headline).frame(maxWidth: .infinity, minHeight: 50)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(24)
        .frame(maxWidth: 460)
    }

    private func point(_ symbol: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).font(.title3).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
