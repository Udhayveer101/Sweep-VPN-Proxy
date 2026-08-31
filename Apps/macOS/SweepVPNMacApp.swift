import SwiftUI
import SweepVPNCore
import SweepVPNKit
import SweepVPNUI

/// macOS surface: a normal single-window app. The window is only a controller —
/// protection itself is enforced by the packet-tunnel and filter extensions, so
/// quitting it does not drop the kill switch.
@main
struct SweepVPNMacApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID))
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
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}
