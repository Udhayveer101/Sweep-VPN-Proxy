import XCTest
@testable import SweepVPNCore

/// The connect/disconnect flapping the user actually saw: every start failed,
/// on-demand restarted the extension instantly, and the cycle never slowed
/// down. These tests pin the shape of the fix — retries get slower, they never
/// stop, and a working tunnel wipes the streak.
final class StartBackoffTests: XCTestCase {

    func testFirstFailureRetriesImmediately() {
        // A one-off failure is usually a server that blinked. Don't punish it.
        XCTAssertEqual(StartBackoff().delay(), 0)
    }

    func testRepeatedFailuresBackOffAndThenPlateau() {
        var b = StartBackoff()
        let now = Date()
        var delays: [TimeInterval] = []
        for _ in 0..<10 {
            b = b.recordingFailure(now: now)
            delays.append(b.delay(now: now))
        }
        // Monotonic, then flat — never decreasing, never unbounded.
        XCTAssertEqual(delays, delays.sorted())
        XCTAssertEqual(delays.last, StartBackoff.delays.last)
        XCTAssertTrue(delays.allSatisfy { $0 <= 120 }, "backoff must stay bounded")
    }

    func testRetriesNeverStopEntirely() {
        var b = StartBackoff()
        let now = Date()
        for _ in 0..<50 { b = b.recordingFailure(now: now) }
        // Fail-closed means we keep trying forever: giving up would either
        // strand the user or leak traffic. Slow is the goal, not stopping.
        XCTAssertLessThan(b.delay(now: now), .infinity)
        XCTAssertEqual(b.delay(now: now), 120)
    }

    func testAuthenticatedTunnelClearsTheStreak() {
        var b = StartBackoff()
        let now = Date()
        for _ in 0..<5 { b = b.recordingFailure(now: now) }
        XCTAssertGreaterThan(b.delay(now: now), 0)

        b = b.recordingSuccess()
        XCTAssertEqual(b.consecutiveFailures, 0)
        XCTAssertEqual(b.delay(now: now), 0)
    }

    func testStaleStreakIsForgottenSoANetworkChangeGetsAFastRetry() {
        let long_ago = Date().addingTimeInterval(-StartBackoff.streakExpiry - 1)
        var b = StartBackoff()
        for _ in 0..<6 { b = b.recordingFailure(now: long_ago) }

        // Same object, evaluated now: the user has moved networks since.
        XCTAssertEqual(b.delay(now: Date()), 0)
        XCTAssertEqual(b.effective(now: Date()).consecutiveFailures, 0)
    }

    func testPersistentBreakageIsDistinguishableFromAFlakyNetwork() {
        var b = StartBackoff()
        let now = Date()
        b = b.recordingFailure(now: now)
        XCTAssertFalse(b.looksPersistentlyBroken)
        b = b.recordingFailure(now: now)
        b = b.recordingFailure(now: now)
        XCTAssertTrue(b.looksPersistentlyBroken,
                      "the UI needs to stop showing a spinner and say what is wrong")
    }

    func testStreakSurvivesAProcessRestart() throws {
        // The extension is torn down between attempts, so the counter only
        // works if it round-trips through shared storage.
        let suite = "sweep.tests.\(UUID().uuidString)"
        defer { UserDefaults().removePersistentDomain(forName: suite) }
        let store = StartBackoffStore(suiteName: suite)

        XCTAssertEqual(store.load().consecutiveFailures, 0)
        store.save(StartBackoff(consecutiveFailures: 4, lastFailureAt: Date()))

        // A brand-new store instance stands in for the relaunched extension.
        let reloaded = StartBackoffStore(suiteName: suite).load()
        XCTAssertEqual(reloaded.consecutiveFailures, 4)
        XCTAssertGreaterThan(reloaded.delay(), 0)
    }
}
