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
    public var serverSwitchMinGainMs: Double = 25
    public init() {}
}

public struct NetworkSignals: Sendable, Equatable {
    public var isExpensive: Bool          // cellular
    public var isLowPowerMode: Bool
    public var isConstrained: Bool        // Low Data Mode
    public var udpBlockedHint: Bool
    public init(isExpensive: Bool = false, isLowPowerMode: Bool = false,
                isConstrained: Bool = false, udpBlockedHint: Bool = false) {
        self.isExpensive = isExpensive
        self.isLowPowerMode = isLowPowerMode
        self.isConstrained = isConstrained
        self.udpBlockedHint = udpBlockedHint
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
    public var successCounts: [Int: Int] = [:]   // rung.rawValue -> successes
    public init() {}
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
                enabledRungs: Set<ProtocolRung> = [.wireGuardUDP, .ikev2, .wireGuardTCP]) {
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
        if let until = memory.udpBlockedUntil, until > now || signals.udpBlockedHint {
            permitted.removeAll { $0.isUDP }
        } else if signals.udpBlockedHint {
            permitted.removeAll { $0.isUDP }
        }
        if permitted.isEmpty { return .failClosed(.allRungsFailed) }

        if let known = memory.lastGoodRung, permitted.contains(known) {
            return .connect(known)
        }
        guard preference.allowsVoluntarySwitching, permitted.count > 1 else {
            return .connect(permitted[0])
        }
        return .race(Array(permitted.prefix(constants.raceMaxConcurrent)))
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
