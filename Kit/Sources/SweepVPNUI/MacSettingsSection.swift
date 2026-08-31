#if os(macOS)
import SwiftUI
import SweepVPNCore
import SweepVPNKit

/// macOS-only controls: the second kill-switch layer, the system extension it
/// runs in, and start-at-login. These have no iOS equivalent, so they live in
/// their own section rather than being faked on both platforms.
public struct MacSettingsSection: View {
    @ObservedObject var model: VPNViewModel
    @State private var extensionStatus: MacSystemExtensionInstaller.Status = .idle
    @State private var filterEnabled = MacFilterController(providerBundleIdentifier: "").isEnabled
    @State private var launchAtLogin = LoginItem.isEnabled
    @State private var loginItemError: String?

    private let installer: MacSystemExtensionInstaller
    private let filter: MacFilterController

    public init(model: VPNViewModel, tunnelExtensionID: String, filterExtensionID: String) {
        self.model = model
        self.installer = MacSystemExtensionInstaller(extensionIdentifier: tunnelExtensionID)
        self.filter = MacFilterController(providerBundleIdentifier: filterExtensionID)
    }

    public var body: some View {
        Section("This Mac") {
            Toggle("Second kill-switch layer", isOn: Binding(
                get: { filterEnabled },
                set: { enabled in
                    filterEnabled = enabled
                    Task {
                        do {
                            enabled ? try await filter.enable() : try await filter.disable()
                        } catch {
                            filterEnabled = filter.isEnabled
                            model.lastError = error.localizedDescription
                        }
                    }
                }))
            Text("A separate content filter that blocks traffic whenever the tunnel is not carrying it — independent of the routing table, so it still holds if a network tries to route traffic around the VPN. macOS does not tell the filter which interface a connection will use, so while the tunnel is up it defers to the tunnel.")
                .font(.footnote).foregroundStyle(.secondary)

            Toggle("Open Sweep at login", isOn: Binding(
                get: { launchAtLogin },
                set: { enabled in
                    do {
                        try LoginItem.setEnabled(enabled)
                        launchAtLogin = LoginItem.isEnabled
                    } catch {
                        loginItemError = error.localizedDescription
                        launchAtLogin = LoginItem.isEnabled
                    }
                }))
            if let loginItemError {
                Text(loginItemError).font(.footnote).foregroundStyle(.red)
            }

            HStack {
                Text("Tunnel system extension")
                Spacer()
                Text(statusText).foregroundStyle(.secondary)
            }
            Button("Install or update extension") {
                installer.activate { status in
                    Task { @MainActor in extensionStatus = status }
                }
            }
            if case .needsUserApproval = extensionStatus {
                Text("Approve Sweep in System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions. Until you do, the second layer is inactive and only the routing-based kill switch is protecting you.")
                    .font(.footnote).foregroundStyle(.orange)
            }
        }
    }

    private var statusText: String {
        switch extensionStatus {
        case .idle: return "Not checked"
        case .installing: return "Installing…"
        case .needsUserApproval: return "Needs approval"
        case .active: return "Active"
        case .rebootRequired: return "Restart required"
        case .failed(let message): return message
        }
    }
}
#endif
