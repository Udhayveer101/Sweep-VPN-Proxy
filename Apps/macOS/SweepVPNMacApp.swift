import SwiftUI
import SweepVPNKit
import SweepVPNUI

/// macOS surface: a menu-bar popover is the primary UI (vault 11-UX), with a
/// window only for Settings/Diagnostics.
@main
struct SweepVPNMacApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID))

    var body: some Scene {
        MenuBarExtra {
            HomeView(model: model)
                .frame(width: 360, height: 420)
                .onAppear { model.onAppear(); loadServers() }
                .onDisappear { model.onDisappear() }
        } label: {
            Image(systemName: model.state.forwardingAllowed ? "lock.shield.fill" : "shield.slash")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
                .frame(width: 460, height: 520)
        }
    }

    private func loadServers() {
        guard let store = try? AppConfig.makeConfigStore(),
              let bundle = try? store.loadBundle() else { return }
        model.load(servers: bundle.servers)
    }
}
