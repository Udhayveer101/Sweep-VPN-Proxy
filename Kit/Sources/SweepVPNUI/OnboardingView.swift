import SwiftUI
import SweepVPNCore

/// First-run screen. On macOS it is the WARP setup guide, shown until this Mac
/// has a WARP registration, because the proxy does nothing without one. On iOS
/// it is permission priming: explain what the system dialog is about to ask
/// *before* it appears (vault 11-UX/Onboarding-And-Permission-Priming).
public struct OnboardingView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        #if os(macOS)
        WarpSetupGuide(model: model, close: { dismiss() })
        #else
        if model.proxyOnly {
            WarpSetupGuide(model: model, close: { dismiss() })
        } else {
            primer
        }
        #endif
    }

    #if os(iOS)
    private var primer: some View {
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
                point("gear.badge", "iOS will ask to add a VPN configuration",
                      "That system prompt is next. Sweep cannot connect without it.")
                point("exclamationmark.triangle", "One honest limit",
                      "On iOS, some traffic to Apple's own services can leave outside the tunnel. No app can change that.")
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
    #endif
}

/// Step-by-step WARP setup for someone who has never opened a terminal. Every
/// value the proxy needs is entered here; nothing has to be edited in code.
struct WarpSetupGuide: View {
    @ObservedObject var model: VPNViewModel
    let close: () -> Void

    @State private var acceptedTerms = false
    @State private var showExtras = false
    @State private var licenseKey = ""
    @State private var teamToken = ""
    @State private var showWorker = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header
                    step(1, "What you need", done: true) {
                        Text("Nothing to buy and no account to create. Sweep's proxy runs on Cloudflare WARP, which is free. You only need an internet connection for the next step.")
                    }
                    step(2, "Register this \(DeviceNoun.current) with WARP", done: model.warpRegistered) {
                        registration
                    }
                    #if os(iOS)
                    step(3, "Turn WARP on", done: false) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Tap **Route this \(DeviceNoun.current) through WARP** on the main screen. The first time, iOS asks to add a VPN configuration: choose **Allow**.")
                            Text("Every app then goes through Cloudflare WARP inside HTTPS that names an ordinary site. It keeps running after you close Sweep.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    #else
                    step(3, "Turn the proxy on", done: false) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("**Whole Mac:** click the gear ⚙︎ on the main screen ▸ **Tor and proxy** ▸ turn on **Route this whole Mac through WARP**. macOS asks for your password once to change the proxy setting.")
                            Text("**One app only:** in the same place turn on **WARP** and **Local proxy**, then set that app's SOCKS5 proxy to `127.0.0.1` port `\(String(model.options.localProxyPort))`.")
                            Text("Turn it off before you quit. Sweep also undoes it when it quits.")
                                .foregroundStyle(.secondary)
                        }
                    }
                    step(4, "Optional: your own relay Worker", done: false) {
                        worker
                    }
                    #endif
                }
                .padding(24)
            }
            Divider()
            HStack {
                Text(model.warpRegistered ? "WARP is set up on this \(DeviceNoun.current)."
                                          : "This guide comes back until WARP is registered.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button(model.warpRegistered ? "Done" : "Set up later") {
                    model.completeOnboarding()
                    close()
                }
                .keyboardShortcut(model.warpRegistered ? .defaultAction : .cancelAction)
            }
            .padding(16)
        }
        #if os(macOS)
        .frame(minWidth: 440, idealWidth: 480, minHeight: 560, idealHeight: 680)
        #endif
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 36, weight: .medium)).foregroundStyle(.green)
            Text("Set up Sweep VPN").font(.title2.weight(.semibold))
            Text("About a minute, and only once. Follow the steps in order.")
                .font(.subheadline).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var registration: some View {
        VStack(alignment: .leading, spacing: 10) {
            if model.warpRegistered {
                Label("Registered. The proxy is ready to use.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                // A key that failed on the first try can still be added later.
                DisclosureGroup("Add a WARP+ license key (optional)", isExpanded: $showExtras) {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("ab12cd34-ef56gh78-ij90kl12", text: $licenseKey)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Button("Apply key") {
                            Task { await model.registerWarp(licenseKey: licenseKey, teamToken: "") }
                        }
                        .disabled(licenseKey.isEmpty || model.warpSetupBusy)
                    }
                    .padding(.top, 6)
                }
            } else {
                Text("This creates a free, anonymous WARP device for this \(DeviceNoun.current). Its keys are saved only on this \(DeviceNoun.current).")

                DisclosureGroup("I have a WARP+ key or a company team token (optional)", isExpanded: $showExtras) {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("WARP+ license key, e.g. ab12cd34-ef56gh78-ij90kl12", text: $licenseKey)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Text("Only if you pay for WARP+. Find it in the Cloudflare 1.1.1.1 app ▸ menu ▸ Account ▸ Key. Leave empty for free WARP.")
                            .foregroundStyle(.secondary)
                        SecureField("Zero Trust team token", text: $teamToken)
                            .textFieldStyle(.roundedBorder)
                        Text("Only if your company or school gave you a Cloudflare Zero Trust team name: open https://<team-name>.cloudflareaccess.com/warp, sign in, and copy the token it shows. Everyone else leaves this empty.")
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 6)
                }

                Toggle(isOn: $acceptedTerms) {
                    // One Text with inline links, so it wraps as a sentence on an iPhone.
                    Text("I accept Cloudflare's [Terms](https://www.cloudflare.com/application/terms/) and [Privacy Policy](https://www.cloudflare.com/application/privacypolicy/)")
                }
                #if os(macOS)
                .toggleStyle(.checkbox)
                #endif

                HStack(spacing: 10) {
                    Button {
                        Task { await model.registerWarp(licenseKey: licenseKey, teamToken: teamToken) }
                    } label: {
                        Text("Register").frame(minWidth: 90)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!acceptedTerms || model.warpSetupBusy)
                    if model.warpSetupBusy {
                        ProgressView().controlSize(.small)
                        Text("Registering…").foregroundStyle(.secondary)
                    }
                }
            }
            if let error = model.warpSetupError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }
        }
    }

    #if os(macOS)
    private var worker: some View {
        DisclosureGroup("Only needed for the Connect (VPN) button, not the proxy", isExpanded: $showWorker) {
            VStack(alignment: .leading, spacing: 8) {
                Text("If your network blocks VPNs, the Connect button can carry its traffic through a Cloudflare Worker you own. Deploy one with `Tools/worker-tunnel/deploy.sh` (needs a free Cloudflare account) and paste the URL and token it prints.")
                    .foregroundStyle(.secondary)
                TextField("https://sweep-relay-mirror.<you>.workers.dev", text: $model.workerURLText)
                    .textFieldStyle(.roundedBorder)
                SecureField("Worker token", text: $model.workerToken)
                    .textFieldStyle(.roundedBorder)
                Button("Save Worker") { model.saveWorkerSettings() }
            }
            .padding(.top, 6)
        }
        .onAppear { model.loadWorkerSettings() }
    }
    #endif

    private func step<Content: View>(_ number: Int, _ title: String, done: Bool,
                                     @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(done ? Color.green : Color.accentColor.opacity(0.15))
                if done {
                    Image(systemName: "checkmark").font(.caption.weight(.bold)).foregroundStyle(.white)
                } else {
                    Text("\(number)").font(.caption.weight(.bold)).foregroundStyle(Color.accentColor)
                }
            }
            .frame(width: 24, height: 24)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.headline)
                content().font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 12, style: .continuous))
    }
}
