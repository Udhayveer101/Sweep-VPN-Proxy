import XCTest
import SweepVPNCore
@testable import SweepVPNUI

/// Guards the fix for "app shows Protected while an unrelated VPN is running".
///
/// The regression was that an unattributed tunnel was rendered as a full
/// `.connected(rung:server:)` with a fabricated rung and server name. These
/// assertions fail if anyone re-introduces that shortcut.
final class StatusHonestyTests: XCTestCase {

    func testVerifyingNeverClaimsProtection() {
        let p = Presentation.make(state: .verifying, serverName: "NL-FREE#1",
                                  killSwitchArmed: true, onDemandArmed: false, quality: nil)
        // It may say "connected", but never the app's affirmative safety word.
        XCTAssertFalse(p.headline.contains("Protected"),
                       "verifying must not assert protection: \(p.headline)")
        // And it must not present an unverified server as fact.
        XCTAssertFalse(p.detail.contains("NL-FREE#1"),
                       "verifying must not attribute a server it has not confirmed")
        XCTAssertFalse(p.showsQuality, "no quality figure exists before IPC answers")
    }

    func testVerifyingDoesNotAllowForwardingClaim() {
        XCTAssertFalse(TunnelState.verifying.forwardingAllowed)
        XCTAssertTrue(TunnelState.verifying.isBlocking)
    }

    /// The connected case is still allowed to make the claim — that path is fed
    /// only by the provider's own IPC status, which is authoritative.
    func testConnectedStillReportsProtected() {
        let p = Presentation.make(state: .connected(rung: .wireGuardUDP, server: "NL-FREE#1"),
                                  serverName: "NL-FREE#1", killSwitchArmed: true,
                                  onDemandArmed: false, quality: nil)
        XCTAssertTrue(p.headline.contains("Protected"))
    }
}
