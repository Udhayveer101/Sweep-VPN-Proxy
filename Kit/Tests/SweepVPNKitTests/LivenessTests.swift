import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// Liveness is protocol-specific, and conflating the two meanings of "handshake
/// age" is what marked every healthy OpenVPN tunnel dead at the three-minute
/// mark — degrading it, arming the kill switch against it, and leaving the user
/// on a blocked-traffic state with the tunnel still nominally connected.
final class TunnelLivenessTests: XCTestCase {

    /// Reports handshake age only, the way every WireGuard rung does.
    private final class HandshakeAdapter: TunnelAdapter, @unchecked Sendable {
        let rung: ProtocolRung = .wireGuardUDP
        var age: Int64
        init(age: Int64) { self.age = age }
        func start(onAuthenticated: @escaping @Sendable () -> Void,
                   onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                   onFailure: @escaping @Sendable (TunnelErrorKind) -> Void) {}
        func send(packets: [Data], protocols: [NSNumber]) {}
        func stop() {}
        func reassert() {}
        var lastHandshakeAgeSeconds: Int64 { age }
        var transferred: (tx: UInt64, rx: UInt64) { (0, 0) }
    }

    func testWireGuardKeepsHandshakeFreshnessAsItsLivenessRule() {
        XCTAssertTrue(HandshakeAdapter(age: 30).sampleLiveness())
        XCTAssertFalse(HandshakeAdapter(age: 300).sampleLiveness(), "a stale handshake is a dead path")
        XCTAssertFalse(HandshakeAdapter(age: -1).sampleLiveness(), "-1 means never handshaked")
    }

    /// Stands in for OpenVPN: a session age that only grows, plus byte counters.
    private final class SessionAdapter: TunnelAdapter, @unchecked Sendable {
        let rung: ProtocolRung = .openVPNTCP
        var sessionAge: TimeInterval
        var rx: UInt64
        private var lastRx: UInt64?
        init(sessionAge: TimeInterval, rx: UInt64) { self.sessionAge = sessionAge; self.rx = rx }
        func start(onAuthenticated: @escaping @Sendable () -> Void,
                   onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                   onFailure: @escaping @Sendable (TunnelErrorKind) -> Void) {}
        func send(packets: [Data], protocols: [NSNumber]) {}
        func stop() {}
        func reassert() {}
        var lastHandshakeAgeSeconds: Int64 { Int64(sessionAge) }
        var transferred: (tx: UInt64, rx: UInt64) { (0, rx) }

        // Mirrors OpenVPNTunnelAdapter's rule.
        func sampleLiveness() -> Bool {
            let previous = lastRx
            lastRx = rx
            if let previous, rx > previous { return true }
            return sessionAge < TunnelLiveness.openVPNQuietGrace
        }
    }

    /// The regression: an OpenVPN session that has been up for 200 s and is
    /// carrying traffic is healthy. The old rule read its ever-growing session
    /// age as a stale WireGuard handshake and declared it dead at 180 s.
    func testLongLivedOpenVPNSessionCarryingTrafficStaysAlive() {
        let adapter = SessionAdapter(sessionAge: 200, rx: 1_000)
        _ = adapter.sampleLiveness()          // establish a baseline sample
        adapter.rx = 2_000                    // bytes arrived since
        XCTAssertTrue(adapter.sampleLiveness())

        // The default rule would have failed it purely on age.
        XCTAssertFalse(adapter.lastHandshakeAgeSeconds < TunnelLiveness.handshakeStaleAfter)
    }

    func testSilentOpenVPNSessionIsDeadOncePastTheGracePeriod() {
        let adapter = SessionAdapter(sessionAge: 200, rx: 1_000)
        _ = adapter.sampleLiveness()
        XCTAssertFalse(adapter.sampleLiveness(), "no bytes and well past the grace period")
    }

    func testYoungOpenVPNSessionIsGivenTimeBeforeSilenceCounts() {
        let adapter = SessionAdapter(sessionAge: 5, rx: 0)
        XCTAssertTrue(adapter.sampleLiveness(), "still inside the opening grace period")
    }
}

/// The rewrite that puts OpenVPN on our loopback listener. Every case here is
/// CRLF because that is what VPN Gate actually ships — an LF-only fixture
/// passes even when the rewrite is completely broken.
final class LoopbackRewriteTests: XCTestCase {
    func testRewritesRemoteInACRLFProfile() throws {
        let profile = "client\r\nproto tcp\r\nremote 219.100.37.196 443\r\nnobind\r\n"
        let out = try XCTUnwrap(OpenVPNTunnelAdapter.pointingAtLoopback(profile, port: 59141))
        XCTAssertTrue(out.contains("remote 127.0.0.1 59141"))
        XCTAssertFalse(out.contains("219.100.37.196"))
        XCTAssertTrue(out.contains("proto tcp"))
    }

    /// A profile listing several relays must not keep a route out: OpenVPN
    /// would fail over to one and be reset by the gateway.
    func testCollapsesEveryRemote() throws {
        let profile = "remote a.example 443\r\nremote b.example 443\r\ncipher AES-256-GCM\r\n"
        let out = try XCTUnwrap(OpenVPNTunnelAdapter.pointingAtLoopback(profile, port: 1))
        XCTAssertEqual(out.components(separatedBy: "remote ").count - 1, 1)
        XCTAssertFalse(out.contains("example"))
    }

    func testNilWhenThereIsNothingToRewrite() {
        XCTAssertNil(OpenVPNTunnelAdapter.pointingAtLoopback("client\r\n# remote here\r\n", port: 1))
    }
}
