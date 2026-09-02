import Foundation

/// Rate-limits how fast the tunnel is allowed to fail and be restarted.
///
/// # The loop this exists to break
///
/// Failing closed means `NEOnDemandRuleConnect` stays armed: whenever the
/// tunnel is down and something wants the network, the system starts the
/// extension again. That is exactly right when the tunnel *can* come up — it is
/// what stops traffic leaking to the physical interface — but when no server
/// will authenticate at all, the provider fails, on-demand immediately restarts
/// it, and it fails again. The user sees the VPN connecting and disconnecting
/// over and over, forever, and the radio never sleeps.
///
/// Disarming on-demand would stop the flapping by letting traffic out in the
/// clear, which is the one thing the design refuses to do. So instead the
/// provider stays fail-closed and simply takes longer and longer to give up:
/// the blackhole is installed the whole time, nothing leaks, and the retries
/// settle to once every few minutes instead of continuously.
///
/// The extension process is torn down between attempts, so the streak has to
/// live outside it — see `StartBackoffStore`.
public struct StartBackoff: Sendable, Equatable {
    /// Consecutive failed starts. Reset the moment a peer authenticates.
    public var consecutiveFailures: Int
    public var lastFailureAt: Date?

    public init(consecutiveFailures: Int = 0, lastFailureAt: Date? = nil) {
        self.consecutiveFailures = consecutiveFailures
        self.lastFailureAt = lastFailureAt
    }

    /// A streak older than this is stale — the network almost certainly changed
    /// (moved to another Wi-Fi, came back from a tunnel, plugged in) and the
    /// user deserves a fast first attempt rather than inheriting yesterday's
    /// backoff.
    public static let streakExpiry: TimeInterval = 600

    /// First few failures retry briskly, because the common case is a server
    /// that is briefly unreachable and will answer on the next try. Past that
    /// it settles at two minutes: still fail-closed, still retrying, but no
    /// longer hammering.
    public static let delays: [TimeInterval] = [0, 2, 5, 15, 30, 60, 120]

    public func effective(now: Date = Date()) -> StartBackoff {
        guard let last = lastFailureAt, now.timeIntervalSince(last) < Self.streakExpiry
        else { return StartBackoff() }
        return self
    }

    /// How long the provider should hold before reporting a start failure, so
    /// that on-demand's restart lands after the delay rather than instantly.
    public func delay(now: Date = Date()) -> TimeInterval {
        let streak = effective(now: now).consecutiveFailures
        guard streak > 0 else { return 0 }
        return Self.delays[min(streak, Self.delays.count - 1)]
    }

    public func recordingFailure(now: Date = Date()) -> StartBackoff {
        StartBackoff(consecutiveFailures: effective(now: now).consecutiveFailures + 1,
                     lastFailureAt: now)
    }

    public func recordingSuccess() -> StartBackoff { StartBackoff() }

    /// True once we have tried enough times to be confident this is a broken
    /// configuration rather than a flaky network — the UI uses it to say so
    /// instead of showing a connecting spinner forever.
    public var looksPersistentlyBroken: Bool { consecutiveFailures >= 3 }
}

/// Persists the streak across extension restarts, in the shared app group so
/// the UI can read it too.
public struct StartBackoffStore: Sendable {
    /// Suite name rather than the `UserDefaults` itself: the object is not
    /// `Sendable`, and this store crosses between the extension and the app.
    private let suiteName: String?
    private let key = "sweep.startBackoff"

    public init(appGroup: String) {
        self.suiteName = appGroup
    }

    /// Test seam — an in-process suite standing in for the app group.
    public init(suiteName: String?) {
        self.suiteName = suiteName
    }

    private var defaults: UserDefaults? {
        suiteName.flatMap { UserDefaults(suiteName: $0) }
    }

    public func load() -> StartBackoff {
        guard let defaults,
              let data = defaults.data(forKey: key),
              let value = try? JSONDecoder().decode(Stored.self, from: data)
        else { return StartBackoff() }
        return StartBackoff(consecutiveFailures: value.consecutiveFailures,
                            lastFailureAt: value.lastFailureAt)
    }

    public func save(_ backoff: StartBackoff) {
        guard let defaults,
              let data = try? JSONEncoder().encode(Stored(consecutiveFailures: backoff.consecutiveFailures,
                                                          lastFailureAt: backoff.lastFailureAt))
        else { return }
        defaults.set(data, forKey: key)
    }

    private struct Stored: Codable {
        var consecutiveFailures: Int
        var lastFailureAt: Date?
    }
}
