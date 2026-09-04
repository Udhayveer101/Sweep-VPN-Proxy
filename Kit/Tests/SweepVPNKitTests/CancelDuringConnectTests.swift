import XCTest
import SweepVPNCore
@testable import SweepVPNKit
@testable import SweepVPNUI

/// Guards the fix for "Connect is greyed out and there is no Cancel".
///
/// The connect path spends most of its time in `ensureConnectable()`, which
/// fetches a relay list and probes up to 40 relays before the tunnel is ever
/// started. Two things conspired during that window: `isBusy` disabled the
/// primary button for its whole duration, and `state` was still `.disconnected`
/// — so the OS had not reported `.connecting` yet and the button still read
/// "Connect". The user got a dead, greyed-out Connect for tens of seconds with
/// no way to back out.
@MainActor
final class CancelDuringConnectTests: XCTestCase {

    private func makeModel() -> VPNViewModel {
        VPNViewModel(configurator: VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel"),
                     appGroup: "group.com.sweep.vpn.tests.\(UUID().uuidString)")
    }

    /// The intent must move the screen to `.connecting` synchronously, before
    /// any awaiting happens — otherwise the button keeps saying "Connect".
    func testPressingConnectImmediatelyOffersCancel() {
        let model = makeModel()
        XCTAssertEqual(model.presentation.primaryAction, .connect)

        model.perform(.connect)

        XCTAssertEqual(model.presentation.primaryAction, .cancel,
                       "the button must become Cancel the moment Connect is pressed, "
                       + "not when the OS eventually reports .connecting")
        XCTAssertEqual(model.presentation.primaryActionTitle, "Cancel")
    }

    /// `HomeView` disables the primary button on `isBusy`. That must never
    /// swallow a cancel, because the busy window *is* the window in which the
    /// user wants out.
    func testCancelIsNeverDisabledByBusy() {
        for state in [TunnelState.connecting(rung: .openVPNTCP),
                      .handshaking(rung: .openVPNTCP),
                      .reconnecting(attempt: 0)] {
            let p = Presentation.make(state: state, serverName: nil, killSwitchArmed: true,
                                      onDemandArmed: false, quality: nil)
            XCTAssertEqual(p.primaryAction, .cancel, "\(state.logLabel) must offer a way out")
            // This mirrors HomeView's `.disabled(isBusy && primaryAction != .cancel)`.
            let disabledWhileBusy = true && (p.primaryAction != .cancel)
            XCTAssertFalse(disabledWhileBusy,
                           "\(state.logLabel): cancel must stay clickable while busy")
        }
    }

    /// Every in-progress state must present a working control, never a dead one.
    func testNoInProgressStateLeavesTheUserWithoutAnAction() {
        for state in [TunnelState.connecting(rung: .wireGuardUDP),
                      .handshaking(rung: .wireGuardUDP),
                      .verifying,
                      .reasserting,
                      .reconnecting(attempt: 3)] {
            let p = Presentation.make(state: state, serverName: nil, killSwitchArmed: true,
                                      onDemandArmed: false, quality: nil)
            XCTAssertFalse(p.primaryActionTitle.isEmpty, "\(state.logLabel) has no button label")
            XCTAssertTrue([.cancel, .disconnect].contains(p.primaryAction),
                          "\(state.logLabel) must offer cancel or disconnect, got \(p.primaryAction)")
        }
    }
}
