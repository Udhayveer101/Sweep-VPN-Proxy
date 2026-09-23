import XCTest
@testable import SweepVPNCore

final class EventLogTests: XCTestCase {
    private var directory: URL!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUp() {
        super.setUp()
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        suite = "sweep.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: directory)
        UserDefaults.standard.removePersistentDomain(forName: suite)
        super.tearDown()
    }

    private func makeLog(process: String = "app") -> EventLog {
        EventLog(directory: directory, defaults: defaults, processName: process)
    }

    func testEntriesRoundTripInOrder() {
        let log = makeLog()
        log.record(phase: "connect", kind: "first")
        log.record(phase: "relay", level: .error, kind: "second", detail: "boom")

        let entries = log.entries()
        XCTAssertEqual(entries.map(\.kind), ["first", "second"])
        XCTAssertEqual(entries[1].level, .error)
        XCTAssertEqual(entries[1].phase, "relay")
        XCTAssertEqual(entries[0].process, "app")
    }

    /// The reason the journal exists: a line written by the extension and a line
    /// written by the app land in the same file, in the order they happened.
    func testBothProcessesAppendToOneJournal() {
        let app = makeLog(process: "app")
        app.record(phase: "connect", kind: "userPressedConnect")
        app.flush()
        let tunnel = makeLog(process: "tunnel")
        tunnel.record(phase: "tunnel", kind: "startTunnelCalled")
        tunnel.flush()

        let entries = makeLog().entries()
        XCTAssertEqual(entries.map(\.process), ["app", "tunnel"])
    }

    /// A run groups one connect attempt and gives every later line an elapsed
    /// time — without it a stalled connect has no measurable duration.
    func testRunGroupsSubsequentEntriesAndStampsElapsed() {
        let log = makeLog()
        log.record(phase: "connect", kind: "beforeRun")
        let run = log.beginRun("user pressed Connect")
        log.record(phase: "relay", kind: "afterRun")

        let entries = log.entries()
        XCTAssertNotEqual(entries[0].run, run, "a line before the run must not be attributed to it")
        XCTAssertEqual(entries.last?.run, run)
        XCTAssertNotNil(entries.last?.elapsedMs)
        XCTAssertGreaterThanOrEqual(entries.last!.elapsedMs!, 0)
    }

    /// A torn or foreign line must not hide the good lines around it.
    func testUndecodableLineIsSkippedNotFatal() throws {
        let log = makeLog()
        log.record(phase: "connect", kind: "good")
        log.flush()
        let url = try XCTUnwrap(log.fileURL)
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("{ not json\n".utf8))
        try handle.close()
        log.record(phase: "connect", kind: "alsoGood")

        XCTAssertEqual(log.entries().map(\.kind), ["good", "alsoGood"])
    }

    func testClearEmptiesTheJournal() {
        let log = makeLog()
        log.record(phase: "connect", kind: "gone")
        log.clear()
        XCTAssertTrue(log.entries().isEmpty)
    }

    /// Addresses stay scrubbed on the way into the journal, exactly as they are
    /// in the diagnostic ring — the log is meant to be safe to hand to someone.
    func testDetailIsScrubbed() {
        let log = makeLog()
        log.record(phase: "worker", kind: "dialled", detail: "connecting to 203.0.113.9")
        XCTAssertFalse(log.entries()[0].detail.contains("203.0.113.9"))
    }

    func testExportedLineCarriesProcessPhaseAndLevel() {
        let log = makeLog(process: "tunnel")
        log.record(phase: "worker", level: .error, kind: "wssFailed", detail: "refused")
        let line = log.export()
        XCTAssertTrue(line.contains("tunnel/worker"))
        XCTAssertTrue(line.contains("ERROR"))
        XCTAssertTrue(line.contains("wssFailed"))
    }

    /// Existing diagnostic kinds must classify without any call site changing.
    func testDiagnosticKindsClassifyIntoPhaseAndLevel() {
        XCTAssertEqual(Diagnostics.phase(for: "wssDialled"), "worker")
        XCTAssertEqual(Diagnostics.phase(for: "relayTunnelUp"), "relay")
        XCTAssertEqual(Diagnostics.phase(for: "ovpn"), "relay")
        XCTAssertEqual(Diagnostics.level(for: "wssFailed"), .error)
        XCTAssertEqual(Diagnostics.level(for: "failClosed"), .error)
        XCTAssertEqual(Diagnostics.level(for: "wssWaiting"), .warn)
        XCTAssertEqual(Diagnostics.level(for: "wssUp"), .info)
    }
}
