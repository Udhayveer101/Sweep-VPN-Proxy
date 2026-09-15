import SwiftUI
import SweepVPNCore

/// Advanced options live here, deliberately off the home screen.
public struct SettingsView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var diagnostics = ""

    public init(model: VPNViewModel) { self.model = model }

    /// The proxy-only release has no tunnel or filter, so their switches would do nothing.
    private var showsVPNSettings: Bool {
        #if os(macOS)
        return !model.proxyOnly
        #else
        return true
        #endif
    }

    public var body: some View {
        NavigationStack {
            Form {
                #if os(macOS)
                Section("WARP setup") {
                    LabeledContent("Status", value: model.warpRegistered ? "Registered on this Mac" : "Not set up")
                    Button(model.warpRegistered ? "Open setup guide" : "Set up WARP") {
                        model.activeSheet = .onboarding
                    }
                    Text("The proxy needs a free WARP registration. The guide walks through it and takes any optional keys.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                #endif
                if showsVPNSettings {
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
                        get: { model.preference },
                        set: { model.apply(preference: $0) })) {
                            ForEach(VPNViewModel.selectableModes, id: \.self) { mode in
                                Text(mode.displayName).tag(mode)
                            }
                        }
                    Text("Automatic tries the routes this network is most likely to allow, and only changes route under strict anti-flap rules. Routes with no server to reach are not offered.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Advanced") {
                    Picker("Force a route", selection: Binding(
                        get: { model.forcedRung },
                        set: { model.apply(forcedRung: $0) })) {
                            Text("Off").tag(ProtocolRung?.none)
                            ForEach(model.selectableRungs, id: \.self) { rung in
                                Text(rung.displayName).tag(ProtocolRung?.some(rung))
                            }
                        }
                    Toggle("Block ads and trackers in DNS", isOn: Binding(
                        get: { model.options.dnsFilteringEnabled },
                        set: { var o = model.options; o.dnsFilteringEnabled = $0; model.apply(options: o) }))
                    Text("Forcing a route disables racing and automatic fallback. Leave it off unless you are debugging a specific network.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                }
                #if os(macOS)
                if showsVPNSettings {
                Section("Blocked sites") {
                    TextField("One domain per line", text: Binding(
                        get: { model.options.blockedDomains.joined(separator: "\n") },
                        set: {
                            var o = model.options
                            o.blockedDomains = $0.split(separator: "\n")
                                .map { String($0).trimmingCharacters(in: .whitespaces) }
                                .filter { !$0.isEmpty }
                            model.apply(options: o)
                        }), axis: .vertical)
                        .lineLimit(3...10)
                        .font(.system(.footnote, design: .monospaced))
                    Text("Blocked at the connection, not just in DNS, so it holds even when the VPN is off. Subdomains are included. Needs the second kill-switch layer below to be on.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                }
                #endif
                #if os(macOS)
                Section("Tor and proxy") {
                    Toggle("Tor over VPN", isOn: Binding(
                        get: { model.options.torEnabled },
                        set: { model.setTor(enabled: $0) }))
                    if let progress = model.torProgressText {
                        Text(progress).font(.footnote).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Text("Runs Tor inside Sweep and sends its circuits through the VPN, so the exit relay sees the VPN server rather than your connection. Connect the VPN first — your ISP blocks Tor directly, and with the VPN up it only sees WireGuard traffic. Without the VPN, Sweep still tries bridges, Snowflake and meek in turn, but none of them completed on this network.")
                        .font(.footnote).foregroundStyle(.secondary)

                    Toggle("Route this whole Mac through WARP", isOn: Binding(
                        get: { model.systemProxyEnabled },
                        set: { model.setEverythingThroughWarp($0) }))
                    if let why = model.systemProxyError {
                        Text(why).font(.footnote).foregroundStyle(.red).textSelection(.enabled)
                    }
                    Text("Starts WARP, starts the local proxy, and sets the Mac's system SOCKS proxy to it — macOS asks for your password each way. Turn it off before quitting Sweep; the app also undoes it on quit, because a system proxy with nothing behind it takes the Mac offline. Apps that ignore the system proxy setting are unaffected, and DNS lookups still go out normally.")
                        .font(.footnote).foregroundStyle(.secondary)

                    Toggle("WARP (Cloudflare, disguised)", isOn: Binding(
                        get: { model.options.warpEnabled },
                        set: { model.setWarp(enabled: $0) }))
                    if let status = model.warpStatusText {
                        Text(status).font(.footnote)
                            .foregroundStyle(model.warpState.isFailed ? .red : .secondary)
                            .textSelection(.enabled)
                    }
                    TextField("WARP SNI", text: Binding(
                        get: { model.options.warpSNI },
                        set: {
                            var o = model.options
                            o.warpSNI = $0.trimmingCharacters(in: .whitespaces)
                            model.apply(options: o)
                        }))
                        .font(.system(.footnote, design: .monospaced))
                        .disabled(model.options.warpEnabled)
                    Text("Sends the local proxy's traffic to Cloudflare WARP inside HTTPS that names an ordinary site, which the network filter lets through. Turn on Local proxy and point a browser at it. Replaces Tor while on. Change the SNI with WARP off.")
                        .font(.footnote).foregroundStyle(.secondary)

                    Toggle("Local proxy", isOn: Binding(
                        get: { model.options.localProxyEnabled },
                        set: { model.setLocalProxy(enabled: $0) }))
                    if case .listening(let port) = model.proxyState {
                        // `\(port)` on its own renders as "1,080" — SwiftUI
                        // gives an Int the locale's grouping separator, which
                        // in a port number reads as a typo.
                        Text("SOCKS5 and HTTP CONNECT on 127.0.0.1:\(String(port)) → \(model.proxyUpstreamLabel)")
                            .font(.footnote).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    } else if case .failed(let why) = model.proxyState {
                        Text(why).font(.footnote).foregroundStyle(.red)
                    }
                    Toggle("Route proxy through Worker", isOn: Binding(
                        get: { model.options.proxyThroughWorker },
                        set: { model.setProxyThroughWorker($0) }))
                        .disabled(!model.options.localProxyEnabled)
                    Text("Each connection travels inside HTTPS to your Cloudflare Worker, which dials the site for you. No VPN profile needed.")
                        .font(.footnote).foregroundStyle(.secondary)

                    Text("Point an individual app at this proxy to send only that app through the tunnel — or through Tor when Tor is on. It listens on this Mac only.")
                        .font(.footnote).foregroundStyle(.secondary)

                    TextField("Bridge lines (one per line, optional)",
                              text: Binding(
                                get: { model.options.torBridges.joined(separator: "\n") },
                                set: {
                                    var o = model.options
                                    o.torBridges = $0.split(separator: "\n")
                                        .map { String($0).trimmingCharacters(in: .whitespaces) }
                                        .filter { !$0.isEmpty }
                                    model.apply(options: o)
                                }),
                              axis: .vertical)
                        .lineLimit(2...6)
                        .font(.system(.footnote, design: .monospaced))
                    Text("Only needed if Tor is blocked and the VPN is not carrying it. Get bridges from bridges.torproject.org — the bridges shipped with Tor Browser are public and widely blocked.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if showsVPNSettings {
                MacSettingsSection(model: model,
                                   tunnelExtensionID: model.tunnelExtensionID,
                                   filterExtensionID: model.filterExtensionID)
                }
                #endif
                if showsVPNSettings {
                SecurityPanel(model: model, signingKeyFingerprint: model.signingKeyFingerprint)
                Section("Configuration") {
                    Text(model.configStatus ?? "No configuration loaded yet.")
                        .font(.footnote).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
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
            .formStyle(.grouped)
            #if os(macOS)
            // A grouped form on macOS lays labels out in a leading column; the
            // extra width keeps the longer ones from clipping in the settings
            // window, and the padding keeps body text off the edge.
            .padding(.horizontal, 8)
            #endif
            .navigationTitle("Settings")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
    }
}

/// Server list. Row 1 is Automatic (connect to whatever is fastest right now),
/// row 2 is the fastest server pinned so it is always one tap away, and the rest
/// are ordered fastest → slowest from live measurements.
/// Server list. Row 1 is Automatic (connect to whatever is fastest right now),
/// row 2 is the fastest server pinned so it is always one tap away, and the rest
/// are ordered fastest → slowest from live measurements.
///
/// Built on a lazy stack rather than `List` so it renders identically inside the
/// macOS menu-bar popover and stays cheap with a few hundred servers.
public struct ServerPickerView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    public init(model: VPNViewModel) { self.model = model }

    private var visibleEntries: [ServerListEntry] {
        guard !search.isEmpty else { return model.listEntries }
        let needle = search.lowercased()
        return model.listEntries.filter { entry in
            switch entry {
            case .automatic: return true
            case .fastest(let s, _), .server(let s, _):
                return s.name.lowercased().contains(needle)
                    || s.countryCode.lowercased().contains(needle)
                    || (s.cityName?.lowercased().contains(needle) ?? false)
            }
        }
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if model.servers.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(visibleEntries) { entry in
                            row(for: entry)
                                .padding(.horizontal, 16).padding(.vertical, 10)
                            Divider().padding(.leading, 16)
                        }
                        footer
                    }
                }
            }
        }
        .frame(minWidth: 320)
    }

    /// An empty list here is not a loading glitch: Sweep will only ever offer
    /// servers that came out of a signature-verified bundle, so "empty" means
    /// "no bundle yet" and has to say so.
    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "server.rack")
                .font(.system(size: 34)).foregroundStyle(.secondary)
            Text("No servers yet").font(.headline)
            Text("Sweep only connects to servers from a configuration bundle signed with your own key. Nothing has been signed into this build yet.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("How to finish setup") { model.activeSheet = .setupGuide }
                .buttonStyle(.borderedProminent)
            Button("Browse public relays") { model.activeSheet = .publicRelays }
                .buttonStyle(.bordered)
            Text("Public relays are volunteer-run and can log you. They are a way around a "
                 + "blocked site, not a substitute for a server of your own.")
                .font(.caption2).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The rows themselves, without the scroll container, so they can be
    /// rendered and inspected off-screen as well as scrolled in the app.
    var content: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(visibleEntries) { entry in
                row(for: entry)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                Divider().padding(.leading, 16)
            }
            footer
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Text("Server").font(.headline)
            Spacer()
            TextField("Search", text: $search)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 160)
            Button("Done") { dismiss() }
        }
        .padding(16)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Speeds are measured from this network. The list re-orders itself as measurements arrive, and again whenever you change network.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("Show servers that need an operator account",
                   isOn: Binding(get: { model.showAccountOnlyServers },
                                 set: { model.setShowAccountOnlyServers($0) }))
                .font(.callout)
            Text("Imported public relay lists are measurable but only carry traffic once this device's key is registered with that operator.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            Button {
                model.activeSheet = .publicRelays
            } label: {
                Label("Browse public relays (VPN Gate)", systemImage: "antenna.radiowaves.left.and.right")
            }
            .buttonStyle(.bordered)
        }
        .padding(16)
    }

    @ViewBuilder
    private func row(for entry: ServerListEntry) -> some View {
        switch entry {
        case .automatic(let fastest):
            Button {
                model.selectAutomatic()
                dismiss()
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "bolt.badge.automatic.fill").foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Automatic").font(.body.weight(.semibold))
                        Text(fastest.map { "Fastest right now — \($0.name)" } ?? "No server measured yet")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.isAutomaticSelected { Image(systemName: "checkmark") }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

        case .fastest(let server, let probe):
            serverRow(server, probe, badge: "Fastest")

        case .server(let server, let probe):
            serverRow(server, probe, badge: nil)
        }
    }

    private func serverRow(_ server: Server, _ probe: ServerProbe?, badge: String?) -> some View {
        Button {
            model.select(server: server)
            dismiss()
        } label: {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(server.name).lineLimit(1)
                        if let badge {
                            Text(badge)
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.tint.opacity(0.15), in: Capsule())
                        }
                        if server.requiresAccount {
                            Image(systemName: "person.badge.key")
                                .font(.caption2).foregroundStyle(.secondary)
                                .accessibilityLabel("needs an operator account")
                        }
                    }
                    HStack(spacing: 6) {
                        Text(server.countryCode)
                        if let provider = server.provider { Text("· \(provider)").lineLimit(1) }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                latency(probe)
                if model.selectedServerID == server.id { Image(systemName: "checkmark") }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(accessibilityText(server, probe, badge: badge))
    }

    @ViewBuilder
    private func latency(_ probe: ServerProbe?) -> some View {
        if let probe, probe.rttMs.isFinite {
            Text("\(Int(probe.rttMs)) ms")
                .font(.caption.monospacedDigit())
                .foregroundStyle(Presentation.Quality
                    .from(rttMs: probe.rttMs, lossFraction: probe.lossFraction).tint)
        } else {
            Text("—").font(.caption).foregroundStyle(.tertiary)
        }
    }

    private func accessibilityText(_ server: Server, _ probe: ServerProbe?, badge: String?) -> String {
        var parts = [server.name]
        if badge != nil { parts.append("fastest server") }
        if let probe, probe.rttMs.isFinite { parts.append("\(Int(probe.rttMs)) milliseconds") }
        if server.requiresAccount { parts.append("needs an operator account") }
        return parts.joined(separator: ", ")
    }
}
