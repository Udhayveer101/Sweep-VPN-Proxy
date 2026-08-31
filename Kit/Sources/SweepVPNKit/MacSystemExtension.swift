#if os(macOS)
import Foundation
import SystemExtensions
import NetworkExtension
import ServiceManagement
import SweepVPNCore

/// Installs and activates the packet-tunnel and content-filter system
/// extensions, and manages the login item. Developer ID distribution ships the
/// providers as system extensions (vault 01-Apple-Platform/macOS-System-Extension-Packaging);
/// the Mac App Store build embeds them as app extensions instead and skips this.
public final class MacSystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate,
                                                @unchecked Sendable {
    public enum Status: Equatable, Sendable {
        case idle
        case installing
        case needsUserApproval   // the user must allow it in System Settings ▸ General ▸ Login Items & Extensions
        case active
        case failed(String)
        case rebootRequired
    }

    private let identifier: String
    private var onStatus: (@Sendable (Status) -> Void)?

    public init(extensionIdentifier: String) {
        self.identifier = extensionIdentifier
    }

    public func activate(onStatus: @escaping @Sendable (Status) -> Void) {
        self.onStatus = onStatus
        onStatus(.installing)
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier,
                                                                 queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func deactivate(onStatus: @escaping @Sendable (Status) -> Void) {
        self.onStatus = onStatus
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier,
                                                                   queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: OSSystemExtensionRequestDelegate

    /// Replacing an extension is always allowed: the pair is signed by us and
    /// shipped together, so refusing an upgrade would only strand the user on an
    /// older tunnel.
    public func request(_ request: OSSystemExtensionRequest,
                        actionForReplacingExtension existing: OSSystemExtensionProperties,
                        withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        onStatus?(.needsUserApproval)
    }

    public func request(_ request: OSSystemExtensionRequest,
                        didFinishWithResult result: OSSystemExtensionRequest.Result) {
        onStatus?(result == .willCompleteAfterReboot ? .rebootRequired : .active)
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        onStatus?(.failed(error.localizedDescription))
    }
}

/// Start-at-login for the menu-bar app. The tunnel itself is armed by the
/// on-demand rule, not by this — a login item only makes the UI available.
public enum LoginItem {
    public static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    public static func setEnabled(_ enabled: Bool) throws {
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }
}

/// Installs and controls the content-filter (second kill-switch layer).
public struct MacFilterController: Sendable {
    public let providerBundleIdentifier: String

    public init(providerBundleIdentifier: String) {
        self.providerBundleIdentifier = providerBundleIdentifier
    }

    /// Enable the filter. It blocks by default, so it must only be enabled once
    /// the user has accepted the kill switch.
    public func enable() async throws {
        let manager = NEFilterManager.shared()
        try await manager.loadFromPreferences()
        if manager.providerConfiguration == nil {
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true
            configuration.filterPackets = false
            manager.providerConfiguration = configuration
            manager.localizedDescription = "Sweep VPN kill switch"
        }
        manager.isEnabled = true
        try await manager.saveToPreferences()
    }

    public func disable() async throws {
        let manager = NEFilterManager.shared()
        try await manager.loadFromPreferences()
        manager.isEnabled = false
        try await manager.saveToPreferences()
    }

    public var isEnabled: Bool { NEFilterManager.shared().isEnabled }
}
#endif
