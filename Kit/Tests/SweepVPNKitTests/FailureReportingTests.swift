import XCTest
import SweepVPNCore
@testable import SweepVPNKit

/// The tunnel used to report every startup failure as "the signed configuration
/// could not be verified", which is wrong for all but one of them and sent every
/// investigation down the config path. These assertions fail if a failure ever
/// again gets a label that does not describe it.
final class FailureReportingTests: XCTestCase {

    func testEachStartupFailureGetsItsOwnKind() {
        XCTAssertEqual(SweepPacketTunnelProvider.kind(for: ConfigError.noServers),
                       .noServersAvailable)
        // No store at all is an environment fault, not a rejected signature.
        XCTAssertEqual(SweepPacketTunnelProvider.kind(for: ConfigError.badSignature),
                       .internalFailure)
        XCTAssertEqual(SweepPacketTunnelProvider.kind(for: ConfigError.malformed),
                       .configurationInvalid)
        XCTAssertEqual(
            SweepPacketTunnelProvider.kind(for: AdapterFactoryError.noEndpoint(.openVPNTCP)),
            .allRungsFailed)
    }

    /// The point of the reason is that it names the cause. A message that could
    /// be printed for any failure is no better than the label it replaced.
    func testExplanationsNameTheActualCause() {
        let noServers = SweepPacketTunnelProvider.explain(ConfigError.noServers)
        XCTAssertTrue(noServers.contains("relay"), noServers)
        XCTAssertFalse(noServers.lowercased().contains("signature"), noServers)

        let noStore = SweepPacketTunnelProvider.explain(ConfigError.badSignature)
        XCTAssertTrue(noStore.contains("keychain"), noStore)

        let missing = SweepPacketTunnelProvider.explain(
            AdapterFactoryError.missingCredential(.openVPNTCP))
        XCTAssertTrue(missing.contains(ProtocolRung.openVPNTCP.displayName), missing)
    }

    /// A reason must outlive the process that produced it, or it is useless in
    /// the one case that matters: a tunnel that dies during startup.
    func testFailureSurvivesInSharedStore() {
        let suite = "sweep.tests.failure.\(UUID().uuidString)"
        let store = TunnelFailureStore(suiteName: suite)
        defer { UserDefaults().removePersistentDomain(forName: suite) }

        XCTAssertNil(store.load())
        store.save(TunnelFailure(kind: TunnelErrorKind.noServersAvailable.rawValue,
                                 detail: "nothing pinned", rung: "OpenVPN (TCP)"))
        XCTAssertEqual(store.load()?.kind, TunnelErrorKind.noServersAvailable.rawValue)
        XCTAssertEqual(store.load()?.rung, "OpenVPN (TCP)")

        store.clear()
        XCTAssertNil(store.load(), "a connect must not leave the reason that preceded it")
    }

    /// The scrubber still applies: a reason is not a licence to log an address.
    func testFailureDetailIsScrubbed() {
        let failure = TunnelFailure(kind: "x", detail: "could not reach 203.0.113.9")
        XCTAssertFalse(failure.detail.contains("203.0.113.9"), failure.detail)
    }
}
