import SwiftUI
import SweepVPNKit
import SweepVPNUI

@main
struct SweepVPNApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID))

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                HomeView(model: model)
                    .navigationTitle("Sweep VPN")
                    .navigationBarTitleDisplayMode(.inline)
            }
            .onAppear { model.onAppear(); loadServers() }
            .onDisappear { model.onDisappear() }
        }
    }

    /// Servers only ever come from the verified bundle — never from the network
    /// directly, never from UserDefaults.
    private func loadServers() {
        guard let store = try? AppConfig.makeConfigStore(),
              let bundle = try? store.loadBundle() else { return }
        model.load(servers: bundle.servers)
    }
}
