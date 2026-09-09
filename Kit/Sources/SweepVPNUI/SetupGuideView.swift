import SwiftUI

/// What is actually missing, in the order it has to be done. This exists because
/// "the signed configuration could not be verified" is a true statement that
/// tells the user nothing they can act on.
public struct SetupGuideView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    public init(model: VPNViewModel) { self.model = model }

    private struct Step: Identifiable {
        let id = UUID()
        let title: String
        let detail: String
        let command: String?
    }

    private var steps: [Step] {
        [
            Step(title: "Create an offline signing key",
                 detail: "Sweep refuses any server list that is not signed by a key you hold. Generate one, then paste the printed public key into SWEEP_CONFIG_SIGNING_KEY in Config/Local.xcconfig.",
                 command: "swift run --package-path Tools/sweep-sign sweep-sign keygen sweep-config.key"),
            Step(title: "Set up a server",
                 detail: "Run the provisioning script on a machine with a public IP. It installs WireGuard, an in-tunnel resolver, and a default-deny firewall.",
                 command: "sudo Server/install.sh my-vps"),
            Step(title: "Build and sign the server list",
                 detail: "Describe the machine in personal.json, turn it into a bundle, and sign it. The private key never leaves this Mac.",
                 command: "sweep-catalog personal personal.json bundle.json\nsweep-sign sign sweep-config.key bundle.json sweep-config.sig.json"),
            Step(title: "Ship the bundle with the app",
                 detail: "Put sweep-config.sig.json in the app resources, or host it and set SWEEP_CONFIG_URL. Either way it is verified against the pinned key before anything can use it.",
                 command: nil),
        ]
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Finish setup").font(.headline)
                Spacer()
                Button("Done") { dismiss() }
            }
            .padding(16)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if let status = model.configStatus {
                        Label(status, systemImage: "info.circle")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(Array(steps.enumerated()), id: \.element.id) { index, step in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(index + 1). \(step.title)").font(.subheadline.weight(.semibold))
                            Text(step.detail).font(.caption).foregroundStyle(.secondary)
                            if let command = step.command {
                                Text(command)
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                                    .padding(8)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(.quaternary, in: .rect(cornerRadius: 6))
                            }
                        }
                    }
                }
                .padding(16)
            }
        }
        .frame(minWidth: 420, minHeight: 480)
    }
}
