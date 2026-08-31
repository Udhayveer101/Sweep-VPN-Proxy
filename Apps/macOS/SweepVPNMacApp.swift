import SwiftUI
import SweepVPNCore
import SweepVPNKit
import SweepVPNUI

/// macOS surface: a menu-bar popover is the primary UI (vault 11-UX), with a
/// window only for Settings/Diagnostics.
@main
struct SweepVPNMacApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID))
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            HomeView(model: model)
                .frame(width: 380, height: 460)
                .onAppear { model.onAppear() }
                .onDisappear { model.onDisappear() }
        } label: {
            Image(systemName: model.state.forwardingAllowed ? "lock.shield.fill" : "shield.slash")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
                .frame(width: 520, height: 620)
        }
    }

    init() {
        // MenuBarExtra content is lazy: without this the app would only load its
        // configuration once the user opened the popover, so a Mac that boots
        // with Sweep in the menu bar would sit there with no server list.
        let model = self.model
        Task { @MainActor in await Self.refreshConfiguration(into: model) }
    }

    static func refreshConfiguration(into model: VPNViewModel) async {
        guard let store = try? AppConfig.makeConfigStore() else {
            model.noteConfigurationFailure("No signing key is pinned in this build.")
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
        } catch {
            model.noteConfigurationFailure("Could not load a verified server list: \(error)")
        }
    }
}

/// The app is a menu-bar agent: no Dock icon, and closing the popover must not
/// terminate it, or the on-demand tunnel loses its controller.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}
