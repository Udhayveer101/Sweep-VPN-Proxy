#if os(macOS)
import XCTest
@testable import SweepVPNKit

/// A shell script stands in for usque: it logs its arguments and behaves like
/// the real binary (writes config.json on register, log.Fatalf on failure).
final class WarpRegistrationTests: XCTestCase {

    func makeFake(exitCode: Int = 0, writesConfig: Bool = true) throws -> (exe: URL, dir: URL, argLog: URL) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("warp-reg-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let argLog = root.appendingPathComponent("args.log")
        let exe = root.appendingPathComponent("usque")
        let script = """
        #!/bin/sh
        echo "$@" >> "\(argLog.path)"
        if [ \(exitCode) -ne 0 ]; then echo "2026/09/15 Failed to register: 403 Forbidden" >&2; exit \(exitCode); fi
        if [ "$3" = "register" ] && [ \(writesConfig ? 1 : 0) -eq 1 ]; then echo '{}' > "$2"; fi
        echo "2026/09/15 Config saved"
        """
        try script.write(to: exe, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: exe.path)
        return (exe, root.appendingPathComponent("warp", isDirectory: true), argLog)
    }

    func lines(_ url: URL) -> [String] {
        ((try? String(contentsOf: url, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
    }

    func testFreeRegistrationCreatesConfigAndAcceptsTermsNonInteractively() async throws {
        let f = try makeFake()
        XCTAssertFalse(WarpRegistration.isRegistered(directory: f.dir))
        try await WarpRegistration.register(executable: f.exe, directory: f.dir)
        XCTAssertTrue(WarpRegistration.isRegistered(directory: f.dir))
        let config = f.dir.appendingPathComponent("config.json").path
        XCTAssertEqual(lines(f.argLog), ["-c \(config) register --accept-tos -n Sweep VPN"])
        let mode = try FileManager.default.attributesOfItem(atPath: config)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600, "the config holds the device private key")
    }

    func testTeamTokenAndLicenseAreBothPassedToUsque() async throws {
        let f = try makeFake()
        try await WarpRegistration.register(licenseKey: " ab12cd34-ef56gh78-ij90kl12\n",
                                            teamToken: "eyJ.tok", executable: f.exe, directory: f.dir)
        let config = f.dir.appendingPathComponent("config.json").path
        XCTAssertEqual(lines(f.argLog), [
            "-c \(config) register --accept-tos -n Sweep VPN --jwt eyJ.tok",
            "-c \(config) account set ab12cd34-ef56gh78-ij90kl12",
        ])
    }

    func testAlreadyRegisteredOnlyAppliesTheKey() async throws {
        let f = try makeFake()
        try await WarpRegistration.register(executable: f.exe, directory: f.dir)
        try await WarpRegistration.register(licenseKey: "ab12cd34-ef56gh78-ij90kl12", executable: f.exe, directory: f.dir)
        XCTAssertEqual(lines(f.argLog).count, 2)
        XCTAssertTrue(lines(f.argLog)[1].hasSuffix("account set ab12cd34-ef56gh78-ij90kl12"))
    }

    func testMalformedKeyIsRejectedBeforeAnythingRuns() async throws {
        let f = try makeFake()
        do {
            try await WarpRegistration.register(licenseKey: "not-a-key", executable: f.exe, directory: f.dir)
            XCTFail("expected failure")
        } catch let e as WarpRegistration.Failure {
            XCTAssertTrue(e.message.contains("license key"))
        }
        XCTAssertTrue(lines(f.argLog).isEmpty)
        XCTAssertFalse(WarpRegistration.isRegistered(directory: f.dir))
    }

    func testUsqueFailureSurfacesItsReason() async throws {
        let f = try makeFake(exitCode: 1)
        do {
            try await WarpRegistration.register(executable: f.exe, directory: f.dir)
            XCTFail("expected failure")
        } catch let e as WarpRegistration.Failure {
            XCTAssertTrue(e.message.contains("403 Forbidden"), e.message)
        }
        XCTAssertFalse(WarpRegistration.isRegistered(directory: f.dir))
    }

    func testSuccessWithoutAConfigIsStillAFailure() async throws {
        let f = try makeFake(writesConfig: false)
        do {
            try await WarpRegistration.register(executable: f.exe, directory: f.dir)
            XCTFail("expected failure")
        } catch is WarpRegistration.Failure {}
    }

    func testMissingBundledUsqueIsExplained() async {
        do {
            try await WarpRegistration.register(executable: nil)
            XCTFail("expected failure")
        } catch let e as WarpRegistration.Failure {
            XCTAssertTrue(e.message.contains("no bundled usque"))
        } catch { XCTFail("\(error)") }
    }

    func testLicenseKeyFormat() {
        XCTAssertTrue(WarpRegistration.isValidLicenseKey("AB12cd34-ef56GH78-ij90kl12"))
        XCTAssertFalse(WarpRegistration.isValidLicenseKey("ab12cd34-ef56gh78"))
        XCTAssertFalse(WarpRegistration.isValidLicenseKey("ab12cd34-ef56gh78-ij90kl1!"))
    }
}
#endif
