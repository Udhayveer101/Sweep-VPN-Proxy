import XCTest
import NetworkExtension
@testable import SweepVPNKit

/// The duplicate-profile bug, pinned.
///
/// `loadManager()` suspends on `loadAllFromPreferences()` between checking its
/// cache and filling it. Concurrent callers — the view model's `onAppear`, its
/// 5-second poll, and a user-driven connect all reach it — used to sail past
/// the empty cache together, and with no Sweep profile installed each built its
/// own `NETunnelProviderManager()`. Saving those produced two "Sweep VPN"
/// entries in the system VPN menu.
///
/// The observable invariant is object identity: however many callers arrive at
/// once, they must all be handed the *same* manager.
final class ConfiguratorSingleFlightTests: XCTestCase {

    func testConcurrentLoadsAllReceiveTheSameManager() async throws {
        let configurator = VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel")

        // `NETunnelProviderManager` is not `Sendable`, so identity is carried
        // out of the group instead of the object — which is precisely the thing
        // under test: one identity means one profile.
        let identities: [ObjectIdentifier]
        do {
            identities = try await withThrowingTaskGroup(of: ObjectIdentifier.self) { group in
                for _ in 0..<8 {
                    group.addTask { ObjectIdentifier(try await configurator.loadManager()) }
                }
                var out: [ObjectIdentifier] = []
                for try await id in group { out.append(id) }
                return out
            }
        } catch {
            // Reading system VPN preferences is not available to every test
            // host. Skip rather than fail: a green run here must mean the
            // invariant held, never that the call quietly went nowhere.
            throw XCTSkip("system VPN preferences unavailable in this test host: \(error)")
        }

        XCTAssertEqual(identities.count, 8)
        XCTAssertEqual(Set(identities).count, 1,
                       "concurrent loadManager() calls handed out \(Set(identities).count) distinct "
                       + "managers — each would save its own profile")
    }

    /// A second, later call must still reuse the cached manager rather than
    /// starting a fresh load.
    func testSequentialLoadReusesTheCachedManager() async throws {
        let configurator = VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel")
        do {
            let a = ObjectIdentifier(try await configurator.loadManager())
            let b = ObjectIdentifier(try await configurator.loadManager())
            XCTAssertEqual(a, b)
        } catch {
            throw XCTSkip("system VPN preferences unavailable in this test host: \(error)")
        }
    }
}
