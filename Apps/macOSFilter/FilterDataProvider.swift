import Foundation
import NetworkExtension
import SweepVPNCore
import SweepVPNKit

/// macOS kill-switch layer 2. Packaging only — the verdict logic lives in
/// `FilterPolicy` in the shared core, where it is unit-tested.
final class FilterDataProvider: SweepFilterDataProvider {
    override var stateStore: FilterStateStore? { FilterStateStore(appGroup: AppConfig.appGroup) }
}
