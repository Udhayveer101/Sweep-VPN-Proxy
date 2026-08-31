import XCTest
@testable import SweepVPNCore

final class ProtocolLadderTests: XCTestCase {
    func testLadderIsOrderedAndComplete() {
        XCTAssertEqual(ProtocolRung.allCases.map(\.rawValue), Array(1...7))
        XCTAssertEqual(ProtocolRung.allCases.first, .wireGuardUDP)
        XCTAssertEqual(ProtocolRung.allCases.last, .wireGuardTCP)
    }

    func testEveryNetworkFailureModeHasAnAnswer() {
        let all = ProtocolRung.allCases
        XCTAssertTrue(all.contains { $0.survivesUDPBlock && $0.usesPacketTunnel },
                      "must have a rung for UDP-blocked networks")
        XCTAssertTrue(all.contains(where: \.looksLikeWeb), "must have a rung that looks like HTTPS")
        XCTAssertTrue(all.contains { $0 == .shadowsocks2022 },
                      "must have a rung with no plaintext handshake to fingerprint")
        XCTAssertTrue(all.contains { !$0.usesPacketTunnel }, "must have a kernel rung for low power")
    }

    func testStealthModeOnlyOffersWebShapedRungs() {
        let rungs = ProtocolPreference.stealth.permittedRungs(enabledTiers: Set(ProtocolRung.allCases))
        XCTAssertFalse(rungs.isEmpty)
        XCTAssertTrue(rungs.allSatisfy(\.looksLikeWeb))
    }

    func testLowPowerModeIsKernelOnly() {
        XCTAssertEqual(ProtocolPreference.lowPower.permittedRungs(
            enabledTiers: Set(ProtocolRung.allCases)), [.ikev2])
    }

    func testRaceSetIsDiverseNotJustTopN() {
        let set = AutoModeEngine.raceSet(from: ProtocolRung.allCases, max: 3)
        XCTAssertEqual(set.count, 3)
        XCTAssertEqual(set.first, .wireGuardUDP)
        XCTAssertTrue(set.contains { $0.survivesUDPBlock })
        XCTAssertTrue(set.contains(where: \.looksLikeWeb))
        XCTAssertEqual(Set(set).count, 3, "no duplicates")
    }

    func testHostileNetworkStartsWithWebShapedRungs() {
        var engine = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        let decision = engine.decideStart(memory: .init(),
                                          signals: .init(hostileNetworkSuspected: true),
                                          now: Date())
        guard case .race(let rungs) = decision else { return XCTFail("expected a race, got \(decision)") }
        XCTAssertTrue(rungs.first?.looksLikeWeb ?? false,
                      "a filtering network should lead with a web-shaped rung")
    }

    func testUDPBlockedNetworkNeverOffersAUDPRung() {
        var engine = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        let decision = engine.decideStart(memory: .init(),
                                          signals: .init(udpBlockedHint: true), now: Date())
        switch decision {
        case .connect(let r): XCTAssertFalse(r.isUDP)
        case .race(let rs): XCTAssertTrue(rs.allSatisfy { !$0.isUDP })
        default: XCTFail("unexpected \(decision)")
        }
    }

    func testLadderWalksAllTheWayDownBeforeGivingUp() {
        var engine = AutoModeEngine(enabledRungs: Set(ProtocolRung.allCases))
        var rung = ProtocolRung.wireGuardUDP
        var seen: [ProtocolRung] = [rung]
        let t0 = Date()
        for step in 0..<ProtocolRung.allCases.count {
            engine.noteConnected(rung: rung, now: t0.addingTimeInterval(Double(step) * 10))
            let bad = LinkHealth(rttMs: 50, lossFraction: 0, handshakeOK: false)
            _ = engine.observe(health: bad, now: t0.addingTimeInterval(Double(step) * 10 + 1))
            let d = engine.observe(health: bad, now: t0.addingTimeInterval(Double(step) * 10 + 2))
            guard case .downgrade(let next, _) = d, next != rung else { break }
            rung = next
            seen.append(next)
        }
        XCTAssertEqual(seen.count, ProtocolRung.allCases.count,
                       "every rung should be tried before the ladder bottoms out: \(seen)")
        XCTAssertEqual(seen.last, .wireGuardTCP)
    }
}

final class ServerCatalogTests: XCTestCase {
    func server(_ id: String, load: Double = 0, requiresAccount: Bool = false) -> Server {
        Server(id: id, name: id, countryCode: "SE", publicKey: "pk",
               endpoints: [.init(host: "10.0.0.1", port: 51820, rung: .wireGuardUDP)],
               dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2",
               load: load, requiresAccount: requiresAccount)
    }

    func catalog() -> ServerCatalog {
        var c = ServerCatalog(servers: [server("slow"), server("fast"), server("mid")])
        c.record(.init(rttMs: 200, lossFraction: 0), for: "slow")
        c.record(.init(rttMs: 12, lossFraction: 0), for: "fast")
        c.record(.init(rttMs: 80, lossFraction: 0), for: "mid")
        return c
    }

    func testRankedIsFastestToSlowest() {
        XCTAssertEqual(catalog().ranked().map(\.0.id), ["fast", "mid", "slow"])
    }

    func testAutomaticIsFirstAndFastestIsSecond() {
        let entries = catalog().listEntries()
        guard case .automatic(let auto) = entries[0] else { return XCTFail("row 1 must be Automatic") }
        XCTAssertEqual(auto?.id, "fast", "Automatic connects to the fastest server")
        guard case .fastest(let pinned, let probe) = entries[1] else {
            return XCTFail("row 2 must be the pinned fastest server")
        }
        XCTAssertEqual(pinned.id, "fast")
        XCTAssertEqual(probe?.rttMs, 12)
        XCTAssertEqual(entries.dropFirst(2).compactMap(\.server?.id), ["mid", "slow"])
    }

    func testFastestSlotFollowsNewMeasurements() {
        var c = catalog()
        c.record(.init(rttMs: 5, lossFraction: 0), for: "slow")   // it just got quicker
        guard case .fastest(let pinned, _) = c.listEntries()[1] else { return XCTFail() }
        XCTAssertEqual(pinned.id, "slow", "row 2 re-evaluates on every measurement")
        XCTAssertEqual(c.fastest()?.id, "slow")
    }

    func testUnmeasuredServersSortAfterMeasuredOnes() {
        var c = catalog()
        c.replaceServers(c.servers + [server("unknown", load: 0.1)])
        XCTAssertEqual(c.ranked().map(\.0.id), ["fast", "mid", "slow", "unknown"])
        XCTAssertNil(c.ranked().last?.1)
    }

    func testGatedServersAreNeverRankedOrPicked() {
        var c = catalog()
        c.record(.init(rttMs: 5, lossFraction: 0.9), for: "fast")  // packet loss over the gate
        XCTAssertEqual(c.fastest()?.id, "mid")
        XCTAssertFalse(c.ranked().prefix(2).contains { $0.0.id == "fast" })
    }

    func testAccountOnlyServersCanBeExcluded() {
        var c = ServerCatalog(servers: [server("mine"), server("relay", requiresAccount: true)])
        c.record(.init(rttMs: 100, lossFraction: 0), for: "mine")
        c.record(.init(rttMs: 5, lossFraction: 0), for: "relay")
        XCTAssertEqual(c.fastest(includeAccountRequired: false)?.id, "mine")
        XCTAssertEqual(c.fastest(includeAccountRequired: true)?.id, "relay")
    }

    func testProbeTargetsAreBoundedAndDeduplicated() {
        var c = ServerCatalog(servers: (0..<50).map { server("s\($0)") })
        c.record(.init(rttMs: 10, lossFraction: 0), for: "s3")
        let targets = c.probeTargets(limit: 5)
        XCTAssertLessThanOrEqual(targets.count, 10)
        XCTAssertEqual(Set(targets.map(\.id)).count, targets.count)
    }

    func testEmptyCatalogStillRendersAutomaticRow() {
        XCTAssertEqual(ServerCatalog().listEntries().count, 1)
        XCTAssertNil(ServerCatalog().fastest())
    }

    func testDNSFilteringSwapsResolverWhenEnabled() {
        var s = server("a")
        s.filteringDNSServers = ["10.64.0.2"]
        var options = SecurityPolicyOptions()
        options.dnsFilteringEnabled = true
        let plan = SecurityPolicy(options: options).connectedPlan(server: s, endpoint: s.endpoints[0])
        XCTAssertEqual(plan.dnsServers, ["10.64.0.2"])
        let plain = SecurityPolicy().connectedPlan(server: s, endpoint: s.endpoints[0])
        XCTAssertEqual(plain.dnsServers, ["10.64.0.1"])
    }
}

final class FilterPolicyTests: XCTestCase {
    func policy(tunnelUp: Bool, killSwitch: Bool = true, lan: Bool = true) -> FilterPolicy {
        var options = SecurityPolicyOptions()
        options.killSwitchEnabled = killSwitch
        options.excludeLocalNetworks = lan
        return FilterPolicy(options: options, tunnelInterface: "utun4", tunnelIsUp: tunnelUp,
                            serverAddresses: ["198.51.100.10"])
    }

    func testEverythingIsDroppedWhileTheTunnelIsDown() {
        let p = policy(tunnelUp: false)
        XCTAssertEqual(p.verdict(for: .init(interfaceName: "en0", remoteAddress: "93.184.216.34")), .drop)
        XCTAssertEqual(p.verdict(for: .init(interfaceName: "utun4", remoteAddress: "93.184.216.34")), .drop)
    }

    func testOnlyTheTunnelInterfaceIsAllowedWhenTheOSRevealsIt() {
        let p = policy(tunnelUp: true)
        XCTAssertEqual(p.verdict(for: .init(interfaceName: "utun4", remoteAddress: "93.184.216.34")), .allow)
        // The TunnelVision case: a route pulled the flow onto Wi-Fi while the
        // tunnel still says "connected". When the interface is visible we drop it.
        XCTAssertEqual(p.verdict(for: .init(interfaceName: "en0", remoteAddress: "93.184.216.34")), .drop)
    }

    /// Documented limit: NEFilterFlow does not publish the interface, so with an
    /// unknown interface and a live tunnel the filter allows. The blocking that
    /// actually matters — everything while the tunnel is down — still holds.
    func testUnknownInterfaceIsAllowedOnlyWhileTheTunnelIsUp() {
        XCTAssertEqual(policy(tunnelUp: true)
            .verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34")), .allow)
        XCTAssertEqual(policy(tunnelUp: false)
            .verdict(for: .init(interfaceName: nil, remoteAddress: "93.184.216.34")), .drop)
    }

    func testTheTunnelsOwnHandshakeIsNeverBlocked() {
        let p = policy(tunnelUp: false)
        XCTAssertEqual(p.verdict(for: .init(interfaceName: "en0", remoteAddress: "198.51.100.10")), .allow)
    }

    func testLANIsAllowedOnlyWhenTheUserAskedForIt() {
        XCTAssertEqual(policy(tunnelUp: false, lan: true)
            .verdict(for: .init(interfaceName: "en0", remoteAddress: "192.168.1.20")), .allow)
        XCTAssertEqual(policy(tunnelUp: false, lan: false)
            .verdict(for: .init(interfaceName: "en0", remoteAddress: "192.168.1.20")), .drop)
    }

    func testLoopbackIsNeverBlocked() {
        XCTAssertEqual(policy(tunnelUp: false)
            .verdict(for: .init(interfaceName: "lo0", remoteAddress: "127.0.0.1", isLoopback: true)), .allow)
    }

    func testFilterIsInertWhenTheKillSwitchIsOff() {
        XCTAssertEqual(policy(tunnelUp: false, killSwitch: false)
            .verdict(for: .init(interfaceName: "en0", remoteAddress: "93.184.216.34")), .allow)
    }

    func testPrivateRangeClassification() {
        for a in ["10.0.0.1", "192.168.0.5", "172.16.3.4", "172.31.255.1", "169.254.1.1",
                  "fd00::1", "fe80::1", "224.0.0.251"] {
            XCTAssertTrue(FilterPolicy.isPrivate(a), "\(a) should be private")
        }
        for a in ["8.8.8.8", "172.32.0.1", "2606:4700::1111", "93.184.216.34"] {
            XCTAssertFalse(FilterPolicy.isPrivate(a), "\(a) should be public")
        }
    }
}
