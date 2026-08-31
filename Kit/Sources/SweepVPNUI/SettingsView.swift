import SwiftUI
import SweepVPNCore

/// Advanced options live here, deliberately off the home screen.
public struct SettingsView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var diagnostics = ""

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        NavigationStack {
            Form {
                Section("Protection") {
                    Toggle("Kill switch", isOn: Binding(
                        get: { model.options.killSwitchEnabled },
                        set: { var o = model.options; o.killSwitchEnabled = $0; model.apply(options: o) }))
                    Toggle("Allow local network access", isOn: Binding(
                        get: { model.options.excludeLocalNetworks },
                        set: { var o = model.options; o.excludeLocalNetworks = $0; model.apply(options: o) }))
                    Text("With the kill switch on, traffic is blocked whenever the tunnel is down. Traffic to Apple's own services can still leave outside the tunnel on iOS — that is an OS behaviour Sweep cannot override.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Connection") {
                    Picker("Mode", selection: Binding(
                        get: { modeIndex },
                        set: { model.apply(preference: preference(for: $0)) })) {
                            Text("Automatic").tag(0)
                            Text("Fast").tag(1)
                            Text("Stealth").tag(2)
                        }
                    Text("Automatic picks the best working route for this network and only changes it under strict anti-flap rules.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Diagnostics") {
                    Button("Export diagnostics") {
                        Task { diagnostics = await model.exportDiagnostics() }
                    }
                    if !diagnostics.isEmpty {
                        ScrollView { Text(diagnostics).font(.caption.monospaced()) }
                            .frame(maxHeight: 220)
                    }
                    Text("Diagnostics contain no IP addresses, domains or DNS names.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }

    private var modeIndex: Int {
        switch model.preference {
        case .automatic: return 0
        case .fast: return 1
        case .stealth: return 2
        case .forced: return 0
        }
    }
    private func preference(for index: Int) -> ProtocolPreference {
        [0: .automatic, 1: .fast, 2: .stealth][index] ?? .automatic
    }
}

public struct ServerPickerView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    public init(model: VPNViewModel) { self.model = model }

    public var body: some View {
        NavigationStack {
            List(model.servers) { server in
                Button {
                    model.select(server: server)
                    dismiss()
                } label: {
                    HStack {
                        VStack(alignment: .leading) {
                            Text(server.name)
                            Text(server.countryCode).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if model.serverName == server.name { Image(systemName: "checkmark") }
                    }
                }
            }
            .navigationTitle("Server")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }
}
