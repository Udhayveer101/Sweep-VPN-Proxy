import XCTest
@testable import SweepVPNCore

final class RoamingDetectorTests: XCTestCase {

    /// The bug this guards: bringing the tunnel up adds a utun, the path
    /// updates, and the old code re-handshaked — over and over, forwarding
    /// gated the whole time.
    func testTunnelComingUpIsNotRoaming() {
        var detector = RoamingDetector()
        XCTAssertEqual(detector.update(satisfied: true, signature: "en0:wifi"), .first)
        // Same Wi-Fi, three more updates as the tunnel installs its settings.
        for _ in 0..<3 {
            XCTAssertEqual(detector.update(satisfied: true, signature: "en0:wifi"), .unchanged)
        }
    }

    func testMovingToAnotherNetworkRoams() {
        var detector = RoamingDetector()
        _ = detector.update(satisfied: true, signature: "en0:wifi")
        XCTAssertEqual(detector.update(satisfied: true, signature: "pdp_ip0:cellular"),
                       .roamed(from: "en0:wifi", to: "pdp_ip0:cellular"))
    }

    /// After the network drops, the next network is a first sighting, not a
    /// roam from a signature that is no longer meaningful.
    func testLossResetsTheComparison() {
        var detector = RoamingDetector()
        _ = detector.update(satisfied: true, signature: "en0:wifi")
        XCTAssertEqual(detector.update(satisfied: false, signature: ""), .lost)
        XCTAssertEqual(detector.update(satisfied: true, signature: "en0:wifi"), .first)
    }
}
