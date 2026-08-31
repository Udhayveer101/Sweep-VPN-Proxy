import XCTest
import CryptoKit
@testable import SweepVPNCore

final class StateMachineTests: XCTestCase {
    func testForwardingOnlyWhenConnected() {
        XCTAssertFalse(TunnelState.disconnected.forwardingAllowed)
        XCTAssertFalse(TunnelState.connecting(rung: .wireGuardUDP).forwardingAllowed)
        XCTAssertFalse(TunnelState.handshaking(rung: .wireGuardUDP).forwardingAllowed)
        XCTAssertFalse(TunnelState.reasserting.forwardingAllowed)
        XCTAssertFalse(TunnelState.killSwitchActive.forwardingAllowed)
        XCTAssertFalse(TunnelState.error(.internalFailure).forwardingAllowed)
        XCTAssertTrue(TunnelState.connected(rung: .wireGuardUDP, server: "a").forwardingAllowed)
    }

    func testIllegalTransitionRejected() {
        var m = StateMachine()
        XCTAssertFalse(m.transition(to: .connected(rung: .wireGuardUDP, server: "a")))
        XCTAssertEqual(m.state, .disconnected)
        XCTAssertTrue(m.transition(to: .connecting(rung: .wireGuardUDP)))
        XCTAssertTrue(m.transition(to: .handshaking(rung: .wireGuardUDP)))
        XCTAssertTrue(m.transition(to: .connected(rung: .wireGuardUDP, server: "a")))
    }

    func testAnyStateCanFailClosed() {
        for s in [TunnelState.connecting(rung: .wireGuardUDP),
                  .connected(rung: .wireGuardUDP, server: "a"), .reasserting] {
            var m = StateMachine()
            m.transition(to: .connecting(rung: .wireGuardUDP))
            if s != .connecting(rung: .wireGuardUDP) {
                m.transition(to: .handshaking(rung: .wireGuardUDP))
                m.transition(to: s)
            }
            XCTAssertTrue(m.transition(to: .killSwitchActive))
            XCTAssertFalse(m.state.forwardingAllowed)
        }
    }
}

final class AutoModeTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    func testLowPowerPrefersIKEv2() {
        var e = AutoModeEngine(enabledRungs: [.wireGuardUDP, .ikev2, .wireGuardTCP])
        let d = e.decideStart(memory: .init(), signals: .init(isLowPowerMode: true), now: t0)
        XCTAssertEqual(d, .connect(.ikev2))
    }

    func testKnownNetworkSkipsRacing() {
        var e = AutoModeEngine()
        var mem = NetworkMemory(); mem.lastGoodRung = .wireGuardTCP
        XCTAssertEqual(e.decideStart(memory: mem, signals: .init(), now: t0), .connect(.wireGuardTCP))
    }

    func testUnknownNetworkRacesTopRungs() {
        var e = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        guard case .race(let rungs) = e.decideStart(memory: .init(), signals: .init(), now: t0) else {
            return XCTFail("expected race")
        }
        XCTAssertEqual(rungs, [.wireGuardUDP, .wireGuardQUIC, .stealthTCP443])
    }

    func testUDPBlockedRemovesUDPRungs() {
        var e = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        var mem = NetworkMemory()
        mem.udpBlockedUntil = t0.addingTimeInterval(600)
        mem.lastGoodRung = .wireGuardUDP     // stale memory must not win
        let d = e.decideStart(memory: mem, signals: .init(), now: t0)
        if case .connect(let r) = d { XCTAssertFalse(r.isUDP) }
        else if case .race(let rs) = d { XCTAssertTrue(rs.allSatisfy { !$0.isUDP }) }
        else { XCTFail("unexpected \(d)") }
    }

    func testForcedPreferenceDisablesRacingAndSwitching() {
        var e = AutoModeEngine(preference: .forced(.ikev2), enabledRungs: Set(ProtocolRung.allCases))
        XCTAssertEqual(e.decideStart(memory: .init(), signals: .init(), now: t0), .connect(.ikev2))
        e.noteConnected(rung: .ikev2, now: t0)
        let d = e.observe(health: .init(rttMs: 10, lossFraction: 0, handshakeOK: true),
                          now: t0.addingTimeInterval(600))
        XCTAssertEqual(d, .stay)
    }

    func testTwoHandshakeFailuresDowngradeImmediately() {
        var e = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        e.noteConnected(rung: .wireGuardUDP, now: t0)
        let bad = LinkHealth(rttMs: 50, lossFraction: 0, handshakeOK: false)
        XCTAssertEqual(e.observe(health: bad, now: t0.addingTimeInterval(1)), .stay)
        // Second failure bypasses the 120 s dwell — a broken tunnel is a reconnect.
        XCTAssertEqual(e.observe(health: bad, now: t0.addingTimeInterval(2)),
                       .downgrade(to: .wireGuardQUIC, reason: .handshakeFlapping))
    }

    func testSustainedLossDowngradesOnlyAfterWindow() {
        var e = AutoModeEngine(enabledRungs: [.wireGuardUDP, .ikev2])
        e.noteConnected(rung: .wireGuardUDP, now: t0)
        let lossy = LinkHealth(rttMs: 50, lossFraction: 0.10, handshakeOK: true)
        XCTAssertEqual(e.observe(health: lossy, now: t0.addingTimeInterval(5)), .stay)
        XCTAssertEqual(e.observe(health: lossy, now: t0.addingTimeInterval(19)), .stay)
        XCTAssertEqual(e.observe(health: lossy, now: t0.addingTimeInterval(26)),
                       .downgrade(to: .ikev2, reason: .highLoss))
    }

    func testUpgradeNeedsCleanProbesDwellAndBudget() {
        var e = AutoModeEngine(enabledRungs: [.wireGuardUDP, .ikev2])
        e.noteConnected(rung: .ikev2, now: t0)
        let good = LinkHealth(rttMs: 30, lossFraction: 0, handshakeOK: true)
        // Inside the 120 s dwell nothing moves, however clean the link is.
        XCTAssertEqual(e.observe(health: good, now: t0.addingTimeInterval(10)), .stay)
        XCTAssertEqual(e.observe(health: good, now: t0.addingTimeInterval(60)), .stay)
        XCTAssertEqual(e.observe(health: good, now: t0.addingTimeInterval(100)), .stay)
        // Past dwell, with 3 clean probes spanning >= 90 s, it climbs.
        XCTAssertEqual(e.observe(health: good, now: t0.addingTimeInterval(200)), .upgrade(to: .wireGuardUDP))
    }

    func testSwitchBudgetAndCooldown() {
        var e = AutoModeEngine()
        e.noteConnected(rung: .ikev2, now: t0)
        for i in 0..<4 { e.recordVoluntarySwitch(now: t0.addingTimeInterval(Double(i))) }
        XCTAssertFalse(e.canSwitchVoluntarily(now: t0.addingTimeInterval(200)))
        XCTAssertTrue(e.canSwitchVoluntarily(now: t0.addingTimeInterval(3700)))
        e.noteFailedSwitch(now: t0.addingTimeInterval(3700))
        XCTAssertFalse(e.canSwitchVoluntarily(now: t0.addingTimeInterval(3800)))
        XCTAssertTrue(e.canSwitchVoluntarily(now: t0.addingTimeInterval(4400)))
    }

    func testKeepalive() {
        XCTAssertNil(KeepalivePolicy.interval(isExpensive: false, isLowPowerMode: true, userActive: true))
        XCTAssertEqual(KeepalivePolicy.interval(isExpensive: false, isLowPowerMode: false, userActive: true), 25)
        XCTAssertEqual(KeepalivePolicy.interval(isExpensive: true, isLowPowerMode: false, userActive: true), 20)
        XCTAssertEqual(KeepalivePolicy.interval(isExpensive: true, isLowPowerMode: false, userActive: false), 60)
    }
}

final class ServerScoringTests: XCTestCase {
    func server(_ id: String, load: Double = 0, rel: Double = 1, jur: Double = 0,
                rung: ProtocolRung = .wireGuardUDP) -> Server {
        Server(id: id, name: id, countryCode: "SE", jurisdictionPenalty: jur, publicKey: "k",
               endpoints: [.init(host: "10.0.0.1", port: 51820, rung: rung)],
               dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2", load: load, reliability: rel)
    }

    func testLossGateDropsServer() {
        let s = server("a")
        XCTAssertFalse(ServerScoring.isEligible(s, .init(rttMs: 10, lossFraction: 0.06), rung: .wireGuardUDP))
        XCTAssertTrue(ServerScoring.isEligible(s, .init(rttMs: 10, lossFraction: 0.04), rung: .wireGuardUDP))
    }

    func testRttGateAndProtocolGate() {
        let s = server("a")
        XCTAssertFalse(ServerScoring.isEligible(s, .init(rttMs: 900, lossFraction: 0), rung: .wireGuardUDP))
        XCTAssertFalse(ServerScoring.isEligible(s, .init(rttMs: 10, lossFraction: 0), rung: .stealthTCP443))
    }

    func testHardAvoidJurisdiction() {
        let s = server("a", jur: .infinity)
        XCTAssertFalse(ServerScoring.isEligible(s, .init(rttMs: 10, lossFraction: 0), rung: .wireGuardUDP))
    }

    func testLowerScoreWins() {
        let fast = (server("fast"), ServerProbe(rttMs: 20, lossFraction: 0))
        let loaded = (server("loaded", load: 0.9), ServerProbe(rttMs: 20, lossFraction: 0))
        XCTAssertEqual(ServerScoring.best(from: [loaded, fast], rung: .wireGuardUDP)?.id, "fast")
    }

    func testDwellAndGainBlockFlapping() {
        let t0 = Date()
        let cur = (server("cur"), ServerProbe(rttMs: 50, lossFraction: 0))
        let rival = (server("rival"), ServerProbe(rttMs: 10, lossFraction: 0))
        XCTAssertFalse(ServerScoring.shouldSwitch(current: cur, rival: rival,
                                                  connectedSince: t0, now: t0.addingTimeInterval(100)))
        XCTAssertTrue(ServerScoring.shouldSwitch(current: cur, rival: rival,
                                                 connectedSince: t0, now: t0.addingTimeInterval(400)))
        let marginal = (server("marginal"), ServerProbe(rttMs: 40, lossFraction: 0))
        XCTAssertFalse(ServerScoring.shouldSwitch(current: cur, rival: marginal,
                                                  connectedSince: t0, now: t0.addingTimeInterval(400)))
    }
}

final class SignedConfigTests: XCTestCase {
    let key = Curve25519.Signing.PrivateKey()
    let now = Date(timeIntervalSince1970: 1_700_000_000)

    func bundle(version: UInt64 = 2, minBuild: Int = 1, expiresIn: TimeInterval = 86_400) -> ConfigBundle {
        ConfigBundle(version: version, issuedAt: now.addingTimeInterval(-60),
                     expiresAt: now.addingTimeInterval(expiresIn), minimumAppBuild: minBuild,
                     servers: [Server(id: "s1", name: "Stockholm", countryCode: "SE", publicKey: "pk",
                                      endpoints: [.init(host: "1.2.3.4", port: 51820, rung: .wireGuardUDP)],
                                      dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")],
                     enabledRungs: [.wireGuardUDP, .ikev2])
    }

    func testValidBundleVerifies() throws {
        let signed = try ConfigVerifier.sign(bundle(), with: key)
        let out = try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                            currentVersion: 1, appBuild: 5, now: now)
        XCTAssertEqual(out.servers.count, 1)
    }

    func testTamperedPayloadRejected() throws {
        var signed = try ConfigVerifier.sign(bundle(), with: key)
        signed.payload[signed.payload.count - 2] ^= 0xFF
        XCTAssertThrowsError(try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                                       currentVersion: nil, appBuild: 5, now: now))
    }

    func testWrongSignerRejected() throws {
        let signed = try ConfigVerifier.sign(bundle(), with: Curve25519.Signing.PrivateKey())
        XCTAssertThrowsError(try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                                       currentVersion: nil, appBuild: 5, now: now)) {
            XCTAssertEqual($0 as? ConfigError, .badSignature)
        }
    }

    func testRollbackRejected() throws {
        let signed = try ConfigVerifier.sign(bundle(version: 3), with: key)
        XCTAssertThrowsError(try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                                       currentVersion: 7, appBuild: 5, now: now)) {
            XCTAssertEqual($0 as? ConfigError, .rollback(have: 7, offered: 3))
        }
    }

    func testExpiredRejected() throws {
        let signed = try ConfigVerifier.sign(bundle(expiresIn: 60), with: key)
        XCTAssertThrowsError(try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                                       currentVersion: nil, appBuild: 5,
                                                       now: now.addingTimeInterval(1000)))
    }

    func testAppTooOldRejected() throws {
        let signed = try ConfigVerifier.sign(bundle(minBuild: 99), with: key)
        XCTAssertThrowsError(try ConfigVerifier.verify(signed, pinnedKey: key.publicKey,
                                                       currentVersion: nil, appBuild: 5, now: now)) {
            XCTAssertEqual($0 as? ConfigError, .appTooOld(required: 99, have: 5))
        }
    }

    func testStoreKeepsLastKnownGoodOnBadUpdate() throws {
        let store = ConfigStore(store: MemoryStore(), pinnedSigningKey: key.publicKey, appBuild: 5)
        _ = try store.accept(try ConfigVerifier.sign(bundle(version: 4), with: key), now: now)
        XCTAssertEqual(store.currentVersion, 4)
        XCTAssertThrowsError(try store.accept(try ConfigVerifier.sign(bundle(version: 2), with: key), now: now))
        XCTAssertEqual(store.currentVersion, 4)
        XCTAssertEqual(try store.loadBundle(now: now)?.version, 4)
    }

    func testDeviceKeysArePersistedAndStable() throws {
        let store = ConfigStore(store: MemoryStore(), pinnedSigningKey: key.publicKey, appBuild: 1)
        let a = try store.devicePrivateKey().rawRepresentation
        let b = try store.devicePrivateKey().rawRepresentation
        XCTAssertEqual(a, b)
    }
}

final class SecurityPolicyTests: XCTestCase {
    let server = Server(id: "s", name: "s", countryCode: "SE", publicKey: "pk",
                        endpoints: [.init(host: "1.2.3.4", port: 51820, rung: .wireGuardUDP)],
                        dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2")

    func testBlackholeIsFailClosed() {
        let plan = SecurityPolicy().blackholePlan()
        XCTAssertFalse(plan.forwardingEnabled)
        XCTAssertEqual(plan.ipv4Routes, [.init("0.0.0.0", 0)])
        XCTAssertEqual(plan.ipv6Routes, [.init("::", 0)])
        XCTAssertTrue(plan.ipv6Blocked)
        XCTAssertEqual(plan.dnsMatchDomains, [""])
    }

    func testIPv6IsNeverLeftToThePhysicalInterface() {
        let plan = SecurityPolicy().connectedPlan(server: server, endpoint: server.endpoints[0])
        XCTAssertTrue(plan.ipv6Blocked)
        XCTAssertEqual(plan.ipv6Routes, [.init("::", 0)])
        var v6 = server; v6.ipv6Address = "fc00::2"
        let plan6 = SecurityPolicy().connectedPlan(server: v6, endpoint: v6.endpoints[0])
        XCTAssertFalse(plan6.ipv6Blocked)
        XCTAssertEqual(plan6.ipv6Routes, [.init("::", 0)])
    }

    func testAllDNSGoesThroughTheTunnel() {
        let plan = SecurityPolicy().connectedPlan(server: server, endpoint: server.endpoints[0])
        XCTAssertEqual(plan.dnsServers, ["10.64.0.1"])
        XCTAssertEqual(plan.dnsMatchDomains, [""])
    }

    func testForwardingGateMatchesState() {
        let p = SecurityPolicy()
        XCTAssertFalse(p.mayForward(state: .handshaking(rung: .wireGuardUDP)))
        XCTAssertFalse(p.mayForward(state: .reasserting))
        XCTAssertTrue(p.mayForward(state: .connected(rung: .wireGuardUDP, server: "s")))
    }

    func testKillSwitchFlags() {
        var o = SecurityPolicyOptions(); o.killSwitchEnabled = false
        XCTAssertFalse(SecurityPolicy(options: o).includeAllNetworks)
        XCTAssertFalse(SecurityPolicy(options: o).onDemandEnabled)
        XCTAssertTrue(SecurityPolicy().includeAllNetworks)
    }
}

final class DiagnosticsTests: XCTestCase {
    func testScrubsAddressesAndDomains() {
        let d = Diagnostics()
        d.record("handshake", "peer 203.0.113.9 sni cloudfront.example.com v6 2001:db8::1")
        let line = d.export()
        XCTAssertFalse(line.contains("203.0.113.9"))
        XCTAssertFalse(line.contains("example.com"))
        XCTAssertFalse(line.contains("2001:db8::1"))
        XCTAssertTrue(line.contains("handshake"))
    }

    func testRingBufferBounded() {
        let d = Diagnostics(capacity: 10)
        for i in 0..<100 { d.record("e", "\(i)") }
        XCTAssertEqual(d.snapshot().count, 10)
    }
}

final class FingerprintTests: XCTestCase {
    func testStableAndSecretDependent() {
        let k1 = SymmetricKey(size: .bits256), k2 = SymmetricKey(size: .bits256)
        let a = NetworkFingerprint.key(deviceSecret: k1, ssid: "home", gatewayMAC: "aa", dnsSuffix: nil, interface: "en0")
        let b = NetworkFingerprint.key(deviceSecret: k1, ssid: "home", gatewayMAC: "aa", dnsSuffix: nil, interface: "en0")
        let c = NetworkFingerprint.key(deviceSecret: k2, ssid: "home", gatewayMAC: "aa", dnsSuffix: nil, interface: "en0")
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        XCTAssertFalse(a.contains("home"))
    }
}

final class IPCTests: XCTestCase {
    func testRoundTrip() throws {
        let status = ProviderStatus(state: .connected(rung: .wireGuardUDP, server: "s1"),
                                    serverName: "Stockholm", rung: .wireGuardUDP,
                                    connectedSince: Date(timeIntervalSince1970: 1), rttMs: 21,
                                    killSwitchArmed: true, pqHybridActive: true)
        let data = try IPCCodec.encode(ProviderToApp.status(status))
        XCTAssertEqual(try IPCCodec.decode(ProviderToApp.self, data), .status(status))
        let msg = AppToProvider.setPreference(.forced(.ikev2))
        XCTAssertEqual(try IPCCodec.decode(AppToProvider.self, try IPCCodec.encode(msg)), msg)
    }
}

final class PostQuantumTests: XCTestCase {
    func testHybridPSKRoundTripWhenAvailable() throws {
        guard #available(iOS 26.0, macOS 26.0, *) else {
            throw XCTSkip("ML-KEM-768 needs iOS/macOS 26")
        }
        let ex = try PostQuantum.Exchange()
        let ek = try MLKEM768.PublicKey(rawRepresentation: ex.encapsulationKey)
        let result = try ek.encapsulate()
        let psk = try ex.psk(from: result.encapsulated)
        let expected = HKDF<SHA256>.deriveKey(inputKeyMaterial: result.sharedSecret,
                                              info: Data("sweep-vpn/wg-psk/v1".utf8),
                                              outputByteCount: 32)
        XCTAssertEqual(psk, expected)
        XCTAssertEqual(psk.bitCount, 256)
    }

    func testOnlyRungs1And2CarryPQ() {
        XCTAssertTrue(ProtocolRung.wireGuardUDP.supportsHybridPQ)
        XCTAssertTrue(ProtocolRung.wireGuardQUIC.supportsHybridPQ)
        XCTAssertFalse(ProtocolRung.ikev2.supportsHybridPQ)
        XCTAssertFalse(ProtocolRung.wireGuardTCP.supportsHybridPQ)
    }
}
