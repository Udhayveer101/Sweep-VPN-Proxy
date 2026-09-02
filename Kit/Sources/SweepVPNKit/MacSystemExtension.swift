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

    /// Reasons activation is refused before it ever reaches the daemon.
    /// These are the overwhelmingly common causes of the generic
    /// "permission denied" a user sees, and none of them are tunnel bugs.
    public static func preflightFailure(bundle: Bundle = .main) -> String? {
        let path = bundle.bundlePath
        // `OSSystemExtensionManager` only accepts requests from an app inside
        // /Applications. Running straight out of DerivedData always fails.
        if !path.hasPrefix("/Applications/") {
            return """
            Sweep must be in /Applications to install its network extension. \
            It is currently running from:
            \(path)

            Move Sweep.app to /Applications and reopen it.
            """
        }
        return nil
    }

    public func activate(onStatus: @escaping @Sendable (Status) -> Void) {
        self.onStatus = onStatus
        if let reason = Self.preflightFailure() {
            onStatus(.failed(reason))
            return
        }
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
        onStatus?(.failed(Self.explain(error)))
    }

    /// `OSSystemExtensionError`'s `localizedDescription` is uniformly unhelpful
    /// ("The operation couldn't be completed"), which is why activation failures
    /// read as an unexplained "permission denied". Map the code to the thing the
    /// user or developer actually has to change.
    static func explain(_ error: Error) -> String {
        let ns = error as NSError
        guard ns.domain == OSSystemExtensionErrorDomain,
              let code = OSSystemExtensionError.Code(rawValue: ns.code) else {
            return error.localizedDescription
        }
        switch code {
        case .validationFailed:
            return """
            The extension's signature or entitlements were rejected.
            Check that the app and the extension are both signed with the same \
            Developer ID team and carry com.apple.developer.networking.networkextension. \
            For local development run: systemextensionsctl developer on
            """
        case .authorizationRequired:
            return "Approve Sweep in System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions."
        case .extensionNotFound:
            return "The extension is missing from the app bundle. Rebuild with `make macos`."
        case .missingEntitlement:
            return "The app is missing the System Extension entitlement. Check Apps/macOS/App.entitlements."
        case .unsupportedParentBundleLocation:
            return "Sweep must be launched from /Applications to install a system extension."
        case .codeSignatureInvalid:
            return """
            Invalid code signature. A build made with CODE_SIGNING_REQUIRED=NO cannot \
            install a system extension — sign with the real Developer ID identity.
            """
        case .duplicateExtensionIdentifer:
            return "Another copy of Sweep is already installed. Remove it, then retry."
        case .requestCanceled, .requestSuperseded:
            return "The install request was superseded. Try again."
        default:
            return "System extension error \(ns.code): \(error.localizedDescription)"
        }
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
