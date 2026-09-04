import SwiftUI
import SystemConfiguration
import SweepVPNCore
import SweepVPNKit
import SweepVPNUI

/// macOS surface: a normal single-window app. The window is only a controller —
/// protection itself is enforced by the packet-tunnel and filter extensions, so
/// quitting it does not drop the kill switch.
@main
struct SweepVPNMacApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID),
        appGroup: AppConfig.appGroup)
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("Sweep VPN", id: "main") {
            HomeView(model: model)
                .frame(minWidth: 420, idealWidth: 460, minHeight: 620, idealHeight: 680)
                .onAppear { model.onAppear() }
                .onDisappear { model.onDisappear() }
                .task { await Self.refreshConfiguration(into: model) }
        }
        .windowResizability(.contentMinSize)
        .commands { CommandGroup(replacing: .newItem) {} }
    }

    static func refreshConfiguration(into model: VPNViewModel) async {
        // The extension cannot read the app's Info.plist, so the tunnel's Worker
        // URL and token are copied into the shared group where it can. Done on
        // every launch so a rebuilt Worker takes effect without extra steps.
        if let url = AppConfig.tunnelURL, !AppConfig.tunnelToken.isEmpty {
            let settings = RelayTunnelSettings(enabled: true, workerURL: url,
                                               token: AppConfig.tunnelToken)
            settings.save(appGroup: AppConfig.appGroup)

            // Resolve the Worker here, where resolution actually works, and
            // leave the answer for the extension. By the time the extension
            // needs it, the previous session's blackhole is usually still
            // installed and its own lookup cannot get out. See
            // `RelayTunnelSettings.cachedAddresses`.
            let group = AppConfig.appGroup
            Task.detached(priority: .utility) {
                // The resolvers go in alongside the Worker. Not hijacking DNS
                // is not the same as DNS working: the blackhole still owns the
                // default route, so a query to the physical interface's
                // resolver is routed into the tunnel and never answered. The
                // Worker's own address is useless without the lookup that
                // produces it.
                let reachable = settings.liveWorkerAddresses(timeout: 5)
                    .union(Self.systemResolvers())
                RelayTunnelSettings.cache(addresses: reachable, appGroup: group)
            }
        }

        // Short fingerprint of the pinned key, so the Security panel can show the
        // user which key this build trusts without exposing the whole value.
        if let key = try? AppConfig.pinnedSigningKey() {
            let raw = key.rawRepresentation.map { String(format: "%02x", $0) }.joined()
            model.signingKeyFingerprint = stride(from: 0, to: min(raw.count, 16), by: 4)
                .map { String(raw.dropFirst($0).prefix(4)) }
                .joined(separator: " ")
        }
        guard let store = try? AppConfig.makeConfigStore() else {
            model.noteConfigurationFailure("No signing key is pinned in this build.",
                                           kind: .notConfigured)
            return
        }
        let fetcher = ConfigFetcher(url: AppConfig.configURL, store: store)
        if let bundle = fetcher.current() {
            model.load(servers: bundle.servers)
            model.noteConfigurationLoaded(version: bundle.version, servers: bundle.servers.count)
        }
        do {
            let refreshed = try await fetcher.refresh()
            model.load(servers: refreshed.servers)
            model.noteConfigurationLoaded(version: refreshed.version, servers: refreshed.servers.count)
        } catch ConfigFetcher.FetchError.notConfigured {
            // Nothing to fetch from and nothing bundled: this build simply has
            // no server list yet. That is setup state, not a security event.
            if !model.hasVerifiedConfig {
                model.noteConfigurationFailure("No server list has been added to this build yet.",
                                               kind: .notConfigured)
            }
        } catch {
            model.noteConfigurationFailure("Could not load a verified server list: \(error)",
                                           kind: model.hasVerifiedConfig ? .configurationInvalid : .notConfigured)
        }
    }

    /// The resolvers this Mac is currently using, read from the system's own
    /// configuration rather than guessed. Empty is a safe answer: the extension
    /// simply excludes one thing less.
    nonisolated static func systemResolvers() -> Set<String> {
        guard let store = SCDynamicStoreCreate(nil, "SweepVPN" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString)
                  as? [String: Any],
              let servers = dns[kSCPropNetDNSServerAddresses as String] as? [String]
        else { return [] }
        // IPv6 resolvers are dropped: the blackhole captures v6 wholesale and
        // excluded routes here are v4-only.
        return Set(servers.filter { !$0.contains(":") })
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

}
