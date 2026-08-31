import XCTest
import CryptoKit
import SweepVPNCore
@testable import SweepVPNKit

/// A URLProtocol that serves whatever the test wants, so the fetcher's
/// fail-closed behaviour is exercised without a network.
final class StubProtocol: URLProtocol {
    nonisolated(unsafe) static var payload: Data?
    nonisolated(unsafe) static var status: Int = 200
    nonisolated(unsafe) static var failure: Error?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        if let error = Self.failure {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.status,
                                       httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if let payload = Self.payload { client?.urlProtocol(self, didLoad: payload) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class ConfigFetcherTests: XCTestCase {
    let signingKey = Curve25519.Signing.PrivateKey()
    let url = URL(string: "https://example.invalid/bundle.json")!

    override func setUp() {
        StubProtocol.payload = nil
        StubProtocol.status = 200
        StubProtocol.failure = nil
    }

    func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: config)
    }

    func bundle(version: UInt64, serverName: String = "A") -> ConfigBundle {
        ConfigBundle(version: version, issuedAt: Date().addingTimeInterval(-60),
                     expiresAt: Date().addingTimeInterval(86_400), minimumAppBuild: 1,
                     servers: [Server(id: "s\(version)", name: serverName, countryCode: "SE",
                                      publicKey: "pk",
                                      endpoints: [.init(host: "1.2.3.4", port: 51820, rung: .wireGuardUDP)],
                                      dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")],
                     enabledRungs: ProtocolRung.allCases)
    }

    func store() -> ConfigStore {
        ConfigStore(store: MemoryStore(), pinnedSigningKey: signingKey.publicKey, appBuild: 5)
    }

    func testFetchesAndPersistsAValidBundle() async throws {
        let store = store()
        StubProtocol.payload = try IPCCodec.encode(ConfigVerifier.sign(bundle(version: 4), with: signingKey))
        let fetched = try await ConfigFetcher(url: url, store: store, session: session()).refresh()
        XCTAssertEqual(fetched.version, 4)
        XCTAssertEqual(store.currentVersion, 4)
    }

    func testABundleSignedByTheWrongKeyIsIgnoredAndTheOldOneStands() async throws {
        let store = store()
        _ = try store.accept(try ConfigVerifier.sign(bundle(version: 4, serverName: "good"), with: signingKey))
        StubProtocol.payload = try IPCCodec.encode(
            ConfigVerifier.sign(bundle(version: 9, serverName: "evil"), with: Curve25519.Signing.PrivateKey()))
        let result = try await ConfigFetcher(url: url, store: store, session: session()).refresh()
        XCTAssertEqual(result.version, 4, "an unsigned update must not take effect")
        XCTAssertEqual(result.servers.first?.name, "good")
        XCTAssertEqual(store.currentVersion, 4)
    }

    func testARollbackIsRefused() async throws {
        let store = store()
        _ = try store.accept(try ConfigVerifier.sign(bundle(version: 7), with: signingKey))
        StubProtocol.payload = try IPCCodec.encode(ConfigVerifier.sign(bundle(version: 2), with: signingKey))
        let result = try await ConfigFetcher(url: url, store: store, session: session()).refresh()
        XCTAssertEqual(result.version, 7)
    }

    func testOfflineKeepsTheLastKnownGoodBundle() async throws {
        let store = store()
        _ = try store.accept(try ConfigVerifier.sign(bundle(version: 5), with: signingKey))
        StubProtocol.failure = URLError(.notConnectedToInternet)
        let result = try await ConfigFetcher(url: url, store: store, session: session()).refresh()
        XCTAssertEqual(result.version, 5)
    }

    func testOfflineWithNothingStoredFailsRatherThanInventingServers() async {
        StubProtocol.failure = URLError(.notConnectedToInternet)
        do {
            _ = try await ConfigFetcher(url: url, store: store(), session: session()).refresh()
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? ConfigFetcher.FetchError, .transport)
        }
    }

    func testNoURLConfiguredIsAnExplicitError() async {
        do {
            _ = try await ConfigFetcher(url: nil, store: store(), session: session()).refresh()
            XCTFail("expected a failure")
        } catch {
            XCTAssertEqual(error as? ConfigFetcher.FetchError, .notConfigured)
        }
    }

    func testGarbageResponseIsRejected() async {
        StubProtocol.payload = Data("not json".utf8)
        do {
            _ = try await ConfigFetcher(url: url, store: store(), session: session()).refresh()
            XCTFail("expected a failure")
        } catch {
            guard case .rejected = (error as? ConfigFetcher.FetchError) else {
                return XCTFail("expected rejection, got \(error)")
            }
        }
    }
}
