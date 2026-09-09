import SwiftUI
import SweepVPNCore

/// Browser for the VPN Gate public relay list: a few hundred volunteer-run
/// OpenVPN servers, measured from this device and ordered fastest first.
///
/// This screen deliberately looks different from `ServerPickerView`. The servers
/// in that one are peers whose keys the user holds; the ones here are strangers'
/// machines that terminate traffic in plaintext and often say outright that they
/// keep logs. The banner and the per-row disclosure are the point of the screen,
/// not decoration around it.
public struct PublicRelayPickerView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var country: String?
    @State private var showingSource = false

    public init(model: VPNViewModel) { self.model = model }

    private var visible: [(Server, ServerProbe?)] {
        var rows = model.rankedRelays
        if let country { rows = rows.filter { $0.0.countryCode == country } }
        let needle = search.lowercased()
        if !needle.isEmpty {
            rows = rows.filter {
                $0.0.name.lowercased().contains(needle)
                    || $0.0.countryCode.lowercased().contains(needle)
                    || ($0.0.cityName?.lowercased().contains(needle) ?? false)
                    || $0.0.endpoints.first.map { "\($0.host)".contains(needle) } ?? false
            }
        }
        return rows
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            trustBanner
            Divider()
            controls
            Divider()
            if model.relays.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(visible, id: \.0.id) { server, probe in
                            row(server, probe)
                                .padding(.horizontal, 16).padding(.vertical, 10)
                            Divider().padding(.leading, 16)
                        }
                    }
                }
            }
            footer
        }
        .frame(minWidth: 380, minHeight: 420)
        .task { model.loadCachedRelays() }
    }

    private var header: some View {
        HStack {
            Text("Public relays").font(.headline)
            Spacer()
            Button("Done") { dismiss() }
        }
        .padding(16)
    }

    /// Stated once, plainly, before the user picks anything.
    private var trustBanner: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.shield")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Run by volunteers, not by you")
                    .font(.caption.weight(.semibold))
                Text("A relay operator can see and log your traffic. These are useful for "
                     + "reaching a blocked site; they are not private. Your own servers stay "
                     + "the default, and Automatic never picks a relay.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
        .background(Color.orange.opacity(0.08))
    }

    private var controls: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search name, country or IP", text: $search)
                    .textFieldStyle(.plain)
            }

            HStack(spacing: 8) {
                Button {
                    Task { await model.refreshRelays() }
                } label: {
                    Label(model.isRefreshingRelays ? "Fetching…" : "Fetch list",
                          systemImage: "arrow.down.circle")
                }
                .disabled(model.isRefreshingRelays)

                Button {
                    Task { await model.probeRelays() }
                } label: {
                    Label(model.isProbingRelays ? "Measuring…" : "Measure speed",
                          systemImage: "speedometer")
                }
                .disabled(model.isProbingRelays || model.relays.isEmpty)

                Spacer()

                if !model.relayCountries.isEmpty {
                    Picker("Country", selection: $country) {
                        Text("All").tag(String?.none)
                        ForEach(model.relayCountries, id: \.self) { code in
                            Text(code).tag(String?.some(code))
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: 110)
                }
            }
            .buttonStyle(.bordered)

            if let status = model.relayStatus {
                Text(status)
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.largeTitle).foregroundStyle(.secondary)
            Text("No relay list yet").font(.body.weight(.semibold))
            Text("Fetch the VPN Gate list to see what is available. If your network blocks "
                 + "vpngate.net, set a mirror URL below first.")
            .font(.caption).foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            Button("Set mirror URL") { showingSource = true }
                .buttonStyle(.bordered)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .popover(isPresented: $showingSource) { sourceEditor }
    }

    private func row(_ server: Server, _ probe: ServerProbe?) -> some View {
        Button {
            model.select(server: server)
            dismiss()
        } label: {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(server.countryCode).font(.body.weight(.semibold))
                        Text(server.name).lineLimit(1).foregroundStyle(.secondary)
                    }
                    HStack(spacing: 6) {
                        if let host = server.endpoints.first?.host { Text(host) }
                        if let rung = server.endpoints.first?.rung { Text("· \(rung.shortName)") }
                        // The operator's own claim, shown as a claim.
                        if let log = server.logPolicy, !log.isEmpty {
                            Text("· logs: \(log)")
                                .foregroundStyle(log.lowercased() == "no" ? Color.secondary : Color.orange)
                        }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1)
                }
                Spacer()
                latency(probe)
                if model.selectedServerID == server.id { Image(systemName: "checkmark") }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private func latency(_ probe: ServerProbe?) -> some View {
        if let probe, probe.lossFraction < 1, probe.rttMs.isFinite {
            Text("\(Int(probe.rttMs)) ms")
                .font(.caption.monospacedDigit())
                .foregroundStyle(probe.rttMs < 120 ? .green : (probe.rttMs < 300 ? .primary : .secondary))
        } else if probe != nil {
            // Measured and did not answer — say so rather than leaving it blank,
            // which reads as "not measured yet".
            Text("no answer").font(.caption).foregroundStyle(.secondary)
        } else {
            Text("—").font(.caption).foregroundStyle(.tertiary)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack {
                if let at = model.relaysFetchedAt {
                    Text("List fetched \(at.formatted(date: .abbreviated, time: .shortened))")
                } else {
                    Text("List never fetched")
                }
                Spacer()
                Button("Mirror URL…") { showingSource = true }
                    .buttonStyle(.plain)
                    .foregroundStyle(.tint)
            }
            .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16).padding(.bottom, 12)
        .popover(isPresented: $showingSource) { sourceEditor }
    }

    private var sourceEditor: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Relay list source").font(.headline)
            Text("Some ISPs block vpngate.net by category. Point this at a mirror you "
                 + "control — a Cloudflare Worker that fetches the CSV and returns it "
                 + "is about fifteen lines — and the app will try it first.")
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            TextField("https://…", text: $model.relaySourceURL)
                .textFieldStyle(.roundedBorder)
            #if os(macOS)
            Divider().padding(.vertical, 4)
            Text("Relay Worker").font(.headline)
            Text("A Worker of your own also carries the relay's own traffic inside "
                 + "HTTPS, which is what gets a connection out of a network that "
                 + "kills OpenVPN on sight. Run Tools/worker-tunnel/deploy.sh and "
                 + "paste what it prints. No build ships one: a shared Worker would "
                 + "mean everyone's traffic on one person's account.")
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            TextField("https://sweep-relay-mirror.….workers.dev", text: $model.workerURLText)
                .textFieldStyle(.roundedBorder)
            SecureField("token", text: $model.workerToken)
                .textFieldStyle(.roundedBorder)
            #endif
            HStack {
                Spacer()
                Button("Fetch now") {
                    #if os(macOS)
                    model.saveWorkerSettings()
                    #endif
                    showingSource = false
                    Task { await model.refreshRelays() }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 340)
        #if os(macOS)
        .onAppear { model.loadWorkerSettings() }
        #endif
    }
}
