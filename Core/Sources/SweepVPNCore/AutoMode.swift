import Foundation

/// Hysteresis constants from vault 12-Synthesis/Recommended-Auto-Mode.
/// UNVERIFIED against real roaming traces — these are the researched estimates
/// and are exposed here so a benchmark run can refit them in one place.
public struct AutoModeConstants: Sendable, Equatable {
    public var minProtocolDwell: TimeInterval = 120
    public var minServerDwell: TimeInterval = 300
    public var rivalMarginFraction: Double = 0.20      // >20% better …
    public var rivalSustained: TimeInterval = 30       // … for >30 s continuous
    public var degradeHandshakeFailures: Int = 2
    public var degradeLossFraction: Double = 0.05      // loss > 5% …
    public var degradeLossWindow: TimeInterval = 20    // … sustained 20 s
    public var recoverCleanProbes: Int = 3
    public var recoverWindow: TimeInterval = 90
    public var failedSwitchCooldown: TimeInterval = 600
    public var maxCooldown: TimeInterval = 7200
    public var maxVoluntarySwitchesPerHour: Int = 4
    public var brokenTunnelGrace: TimeInterval = 8     // bypasses all dwell
    public var raceStagger: TimeInterval = 0.25
    public var raceMaxConcurrent: Int = 3
    public var raceDeadline: TimeInterval = 3
    /// Deadline for rungs that cannot possibly authenticate inside
    /// `raceDeadline`. A WireGuard handshake is one round trip and lands in well
    /// under a second; OpenVPN negotiates TLS, waits for PUSH_REPLY, and on this
    /// network does all of it inside a WSS session to Cloudflare — 5-15 s is
    /// normal. Cutting those off at 3 s abandoned the attempt every time.
    /// Must stay below the provider's handshake deadline, which is the outer bound.
    public var slowRungDeadline: TimeInterval = 25
    public var serverSwitchMinGainMs: Double = 25
    /// How long a relay carries the tunnel before its replacement is warmed
    /// alongside it. On third-party relays a drop is the normal course of a
    /// session — VPN Gate volunteers FIN at 62 s idle, 92 s live by our own
    /// measurement — so the replacement has to be authenticated *before* the
    /// drop or every one of them costs a full OpenVPN handshake of dead tunnel.
    /// Under the shortest observed FIN, so the standby is ready in time.
    public var standbyLeadTime: TimeInterval = 40
    public init() {}
}

public struct NetworkSignals: Sendable, Equatable {
    public var isExpensive: Bool          // cellular
    public var isLowPowerMode: Bool
    public var isConstrained: Bool        // Low Data Mode
    public var udpBlockedHint: Bool
    /// Set when the network looks like it is filtering, not merely lossy — a
    /// captive/DPI network where plain tunnels die but HTTPS lives
    /// (Surfshark-NoBorders-class auto-evasion, vault 04-VPN-Products).
    public var hostileNetworkSuspected: Bool
    public init(isExpensive: Bool = false, isLowPowerMode: Bool = false,
                isConstrained: Bool = false, udpBlockedHint: Bool = false,
                hostileNetworkSuspected: Bool = false) {
        self.isExpensive = isExpensive
        self.isLowPowerMode = isLowPowerMode
        self.isConstrained = isConstrained
        self.udpBlockedHint = udpBlockedHint
        self.hostileNetworkSuspected = hostileNetworkSuspected
    }
}

public struct LinkHealth: Sendable, Equatable {
    public var rttMs: Double
    public var lossFraction: Double
    public var handshakeOK: Bool
    public init(rttMs: Double, lossFraction: Double, handshakeOK: Bool) {
        self.rttMs = rttMs; self.lossFraction = lossFraction; self.handshakeOK = handshakeOK
    }
}

/// Per-network memory, stored on device only, keyed by an HMAC fingerprint.
public struct NetworkMemory: Codable, Sendable, Equatable {
    public var lastGoodRung: ProtocolRung?
    public var udpBlockedUntil: Date?
    public var hostileUntil: Date?
    public var successCounts: [Int: Int] = [:]   // rung.rawValue -> successes
    public var lastSeen: Date?
    public init() {}

    public func isUDPBlocked(now: Date) -> Bool { (udpBlockedUntil ?? .distantPast) > now }
    public func isHostile(now: Date) -> Bool { (hostileUntil ?? .distantPast) > now }

    /// A network that just refused every UDP rung is remembered for a while, so
    /// the next connect there does not waste the race deadline on UDP again.
    public mutating func noteUDPBlocked(now: Date, ttl: TimeInterval = 6 * 3600) {
        udpBlockedUntil = now.addingTimeInterval(ttl)
    }

    public mutating func noteHostile(now: Date, ttl: TimeInterval = 6 * 3600) {
        hostileUntil = now.addingTimeInterval(ttl)
    }

    public mutating func noteSuccess(rung: ProtocolRung, now: Date) {
        lastGoodRung = rung
        lastSeen = now
        successCounts[rung.rawValue, default: 0] += 1
        if rung.isUDP { udpBlockedUntil = nil }
    }
}

public enum AutoDecision: Equatable, Sendable {
    case connect(ProtocolRung)
    case race([ProtocolRung])
    case stay
    case downgrade(to: ProtocolRung, reason: DegradeReason)
    case upgrade(to: ProtocolRung)
    case failClosed(TunnelErrorKind)
}

/// Pure decision engine — no I/O, no timers, fully unit-testable.
/// Callers feed it observations with an explicit `now` so tests control time.
public struct AutoModeEngine: Sendable {
    public var constants: AutoModeConstants
    public var preference: ProtocolPreference
    public var enabledRungs: Set<ProtocolRung>

    private var currentRung: ProtocolRung?
    private var rungSince: Date?
    private var consecutiveHandshakeFailures = 0
    private var lossOverThresholdSince: Date?
    private var cleanProbes: [Date] = []
    private var voluntarySwitches: [Date] = []
    private var cooldownUntil: Date?
    private var cooldown: TimeInterval

    public init(constants: AutoModeConstants = .init(),
                preference: ProtocolPreference = .automatic,
                enabledRungs: Set<ProtocolRung> = Set(ProtocolRung.allCases)) {
        self.constants = constants
        self.preference = preference
        self.enabledRungs = enabledRungs
        self.cooldown = constants.failedSwitchCooldown
    }

    public var activeRung: ProtocolRung? { currentRung }

    /// Decide how to start on a (possibly known) network.
    public mutating func decideStart(memory: NetworkMemory, signals: NetworkSignals, now: Date) -> AutoDecision {
        var permitted = preference.permittedRungs(enabledTiers: enabledRungs)
        if permitted.isEmpty { return .failClosed(.allRungsFailed) }

        // Low Power Mode explicitly prefers the kernel IKEv2 rung when it is permitted.
        if signals.isLowPowerMode, permitted.contains(.ikev2) {
            return .connect(.ikev2)
        }
        // An unexpired "UDP blocked" flag removes the UDP rungs from this network.
        if memory.isUDPBlocked(now: now) || signals.udpBlockedHint {
            permitted.removeAll { $0.isUDP }
        }
        if permitted.isEmpty { return .failClosed(.allRungsFailed) }

        // A filtering network gets the web-shaped rungs first, without waiting
        // for the plain ones to fail.
        if signals.hostileNetworkSuspected || memory.isHostile(now: now) {
            let web = permitted.filter(\.looksLikeWeb)
            if !web.isEmpty { permitted = web + permitted.filter { !$0.looksLikeWeb } }
        }

        if let known = memory.lastGoodRung, permitted.contains(known) {
            return .connect(known)
        }
        guard preference.allowsVoluntarySwitching, permitted.count > 1 else {
            return .connect(permitted[0])
        }
        return .race(Self.raceSet(from: permitted, max: constants.raceMaxConcurrent))
    }

    /// Race a *diverse* set, not the top N by preference: racing three rungs
    /// that all fail the same way (all UDP) wastes the whole 3 s deadline.
    /// One preferred rung + one that survives a UDP block + one that looks like
    /// ordinary web traffic covers the three ways a network usually breaks.
    static func raceSet(from permitted: [ProtocolRung], max: Int) -> [ProtocolRung] {
        var chosen: [ProtocolRung] = []
        func add(_ rung: ProtocolRung?) {
            guard let rung, !chosen.contains(rung), chosen.count < max else { return }
            chosen.append(rung)
        }
        add(permitted.first)
        add(permitted.first(where: \.survivesUDPBlock))
        add(permitted.first(where: \.looksLikeWeb))
        for rung in permitted { add(rung) }
        return chosen
    }

    public mutating func noteConnected(rung: ProtocolRung, now: Date) {
        currentRung = rung
        rungSince = now
        consecutiveHandshakeFailures = 0
        lossOverThresholdSince = nil
        cleanProbes.removeAll()
    }

    /// Feed periodic health. Returns the ladder move to make, if any.
    public mutating func observe(health: LinkHealth, now: Date) -> AutoDecision {
        guard let rung = currentRung else { return .stay }

        if !health.handshakeOK {
            consecutiveHandshakeFailures += 1
        } else {
            consecutiveHandshakeFailures = 0
        }

        if health.lossFraction > constants.degradeLossFraction {
            if lossOverThresholdSince == nil { lossOverThresholdSince = now }
        } else {
            lossOverThresholdSince = nil
        }

        let lossSustained = lossOverThresholdSince.map {
            now.timeIntervalSince($0) >= constants.degradeLossWindow
        } ?? false
        let handshakeDead = consecutiveHandshakeFailures >= constants.degradeHandshakeFailures

        // Down-ladder: fast, and it bypasses dwell — a broken tunnel is a reconnect.
        if handshakeDead || lossSustained {
            let permitted = preference.permittedRungs(enabledTiers: enabledRungs)
            guard preference.allowsVoluntarySwitching,
                  let next = permitted.first(where: { $0 > rung }) else {
                return .downgrade(to: rung, reason: handshakeDead ? .handshakeFlapping : .highLoss)
            }
            consecutiveHandshakeFailures = 0
            lossOverThresholdSince = nil
            return .downgrade(to: next, reason: handshakeDead ? .handshakeFlapping : .highLoss)
        }

        // Up-ladder: slow. Needs clean probes over a window, dwell, budget and no cooldown.
        guard preference.allowsVoluntarySwitching else { return .stay }
        let permitted = preference.permittedRungs(enabledTiers: enabledRungs)
        guard let preferred = permitted.first, preferred < rung else { return .stay }
        guard health.handshakeOK, health.lossFraction <= constants.degradeLossFraction else { return .stay }

        cleanProbes.append(now)
        cleanProbes.removeAll { now.timeIntervalSince($0) > constants.recoverWindow * 4 }
        let inWindow = cleanProbes.filter { now.timeIntervalSince($0) <= constants.recoverWindow * 4 }
        guard inWindow.count >= constants.recoverCleanProbes,
              let first = inWindow.first, now.timeIntervalSince(first) >= constants.recoverWindow
        else { return .stay }

        guard canSwitchVoluntarily(now: now) else { return .stay }
        cleanProbes.removeAll()
        recordVoluntarySwitch(now: now)
        return .upgrade(to: preferred)
    }

    /// A voluntary switch is allowed only outside cooldown, past the dwell time,
    /// and under the per-hour cap.
    public func canSwitchVoluntarily(now: Date) -> Bool {
        if let until = cooldownUntil, now < until { return false }
        if let since = rungSince, now.timeIntervalSince(since) < constants.minProtocolDwell { return false }
        let recent = voluntarySwitches.filter { now.timeIntervalSince($0) < 3600 }
        return recent.count < constants.maxVoluntarySwitchesPerHour
    }

    public mutating func recordVoluntarySwitch(now: Date) {
        voluntarySwitches.append(now)
        voluntarySwitches.removeAll { now.timeIntervalSince($0) >= 3600 }
    }

    /// Exponential backoff after a switch that did not pan out.
    public mutating func noteFailedSwitch(now: Date) {
        cooldownUntil = now.addingTimeInterval(cooldown)
        cooldown = min(cooldown * 2, constants.maxCooldown)
    }

    public mutating func noteSuccessfulSwitch() {
        cooldown = constants.failedSwitchCooldown
        cooldownUntil = nil
    }
}
