import SwiftUI
import SweepVPNCore
import SweepVPNKit
import SweepVPNUI

@main
struct SweepVPNApp: App {
    @StateObject private var model = VPNViewModel(
        configurator: VPNConfigurator(bundleIdentifier: AppConfig.tunnelBundleID),
        appGroup: AppConfig.appGroup)
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                HomeView(model: model)
                    .navigationTitle("Sweep VPN")
                    .navigationBarTitleDisplayMode(.inline)
            }
            .task { await refreshConfiguration() }
            .onAppear { model.onAppear() }
            .onDisappear { model.onDisappear() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { Task { await refreshConfiguration() } }
            }
        }
    }

    /// Servers only ever come from the verified bundle — never straight off the
    /// network, never from UserDefaults.
    private func refreshConfiguration() async {
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
