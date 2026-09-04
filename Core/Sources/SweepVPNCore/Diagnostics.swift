import Foundation
import os

/// Privacy-safe structured event log. No IPs, no domains, no SNIs — enforced by
/// the scrubber, not by convention.
public struct DiagnosticEvent: Codable, Sendable, Equatable {
    public var at: Date
    public var kind: String
    public var detail: String
    public init(at: Date, kind: String, detail: String) {
        self.at = at; self.kind = kind; self.detail = Diagnostics.scrub(detail)
    }
}

/// The last reason the tunnel refused to come up, in words the user can act on.
///
/// This is deliberately written to the shared app group rather than answered
/// over IPC. The extension's diagnostic ring lives only inside the extension
/// process and is readable solely by asking that process — so in the one case
/// where the reason matters most, a tunnel that dies during startup, there was
/// nothing left alive to ask and the app could only say "connecting" forever.
public struct TunnelFailure: Codable, Sendable, Equatable {
    public var at: Date
    /// The `TunnelErrorKind` rawValue, so the UI can pick its own wording.
    public var kind: String
    /// What actually went wrong, already scrubbed of addresses and hostnames.
    public var detail: String
    /// Which rung was being attempted, if one had been chosen yet.
    public var rung: String?
    /// The last events before the failure, oldest first — the sequence that
    /// says *where* a connect died rather than only that it did. Carried here
    /// because the system log is not always readable after the fact, and the
    /// ring that holds these dies with the extension.
    public var trail: [String]

    public init(at: Date = Date(), kind: String, detail: String,
                rung: String? = nil, trail: [String] = []) {
        self.at = at
        self.kind = kind
        self.detail = Diagnostics.scrub(detail)
        self.rung = rung
        self.trail = trail
    }
}

public struct TunnelFailureStore: Sendable {
    private let suiteName: String?
    private let key = "sweep.lastFailure"

    public init(appGroup: String) { self.suiteName = appGroup }
    /// Test seam.
    public init(suiteName: String?) { self.suiteName = suiteName }

    private var defaults: UserDefaults? {
        suiteName.flatMap { UserDefaults(suiteName: $0) }
    }

    public func load() -> TunnelFailure? {
        guard let defaults, let data = defaults.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(TunnelFailure.self, from: data)
    }

    public func save(_ failure: TunnelFailure) {
        guard let defaults, let data = try? JSONEncoder().encode(failure) else { return }
        defaults.set(data, forKey: key)
    }

    /// Cleared on a successful connect so a stale reason cannot be shown beside
    /// a working tunnel.
    public func clear() { defaults?.removeObject(forKey: key) }
}

public final class Diagnostics: @unchecked Sendable {
    /// One ring per process, so components that are handed no diagnostics
    /// object — the adapters and transports, which are built by a factory —
    /// still land in the same trail as the provider that owns them. Without
    /// this their events existed only in the system log, which is not always
    /// readable after the process that wrote it has exited.
    public static let shared = Diagnostics()

    private let capacity: Int
    private var buffer: [DiagnosticEvent] = []
    private let lock = NSLock()   // ponytail: one lock, ring buffer is not hot

    public init(capacity: Int = 512) {
        self.capacity = capacity
        buffer.reserveCapacity(capacity)
    }

    /// Mirrors events to the system log as well as the ring.
    ///
    /// The ring only lives in the process that wrote it and is readable solely
    /// over IPC, so when the tunnel extension failed before it could answer any
    /// IPC — which is exactly when one needs it — the failure left no trace at
    /// all anywhere on the machine. The detail string is already scrubbed of
    /// addresses and hostnames by `DiagnosticEvent.init`, so this publishes
    /// nothing the ring did not already hold.
    private static let log = Logger(subsystem: "com.sweep.vpn", category: "diagnostics")

    public func record(_ kind: String, _ detail: String = "", at: Date = Date()) {
        let event = DiagnosticEvent(at: at, kind: kind, detail: detail)
        // `.notice`, not `.info`: info-level records live in a memory buffer
        // that is discarded when the process exits, and the extension exits on
        // every failed start — so the one process whose logs matter left none.
        Self.log.notice("\(kind, privacy: .public) \(event.detail, privacy: .public)")
        // Mirrored into the shared journal here rather than at each of the ~50
        // call sites: every component that already records a diagnostic becomes
        // visible in the log the user can open, without any of them knowing the
        // log exists. The ring stays because `tail(_:)` still builds the trail
        // stapled to a failure.
        EventLog.shared.record(phase: Self.phase(for: kind), level: Self.level(for: kind),
                               kind: kind, detail: event.detail)
        lock.lock(); defer { lock.unlock() }
        buffer.append(event)
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
    }

    /// Classifies an existing diagnostic kind into a journal phase, so the ~50
    /// call sites that predate the journal group sensibly without being touched.
    /// Unknown kinds land in "tunnel", which is where the bulk of them are.
    static func phase(for kind: String) -> String {
        let k = kind.lowercased()
        if k.hasPrefix("wss") || k.contains("worker") { return "worker" }
        if k.hasPrefix("ovpn") || k.contains("relaytunnel") { return "relay" }
        if k.contains("config") || k.contains("catalog") { return "config" }
        if k.contains("filter") { return "filter" }
        if k.contains("rung") || k.contains("ladder") || k.contains("handshake") { return "ladder" }
        return "tunnel"
    }

    /// A kind that names a failure must not be filtered out as routine detail —
    /// the whole point of the level is that "show me only what went wrong"
    /// leaves the failure visible.
    static func level(for kind: String) -> LogEntry.Level {
        let k = kind.lowercased()
        if k.contains("fail") || k.contains("refused") || k.contains("error")
            || k.contains("denied") || k.contains("closed") { return .error }
        if k.contains("waiting") || k.contains("retry") || k.contains("backoff")
            || k.contains("unrewritten") || k.contains("ended") { return .warn }
        return .info
    }

    public func snapshot() -> [DiagnosticEvent] {
        lock.lock(); defer { lock.unlock() }
        return buffer
    }

    /// The most recent events as short strings, oldest first.
    public func tail(_ count: Int) -> [String] {
        snapshot().suffix(count).map { event in
            let stamp = event.at.formatted(date: .omitted, time: .standard)
            return event.detail.isEmpty
                ? "\(stamp) \(event.kind)"
                : "\(stamp) \(event.kind): \(event.detail)"
        }
    }

    public func export() -> String {
        snapshot().map { "\(ISO8601DateFormatter().string(from: $0.at)) \($0.kind) \($0.detail)" }
            .joined(separator: "\n")
    }

    // IPv4 literals, IPv6 literals, and anything that looks like a hostname.
    private static let patterns: [NSRegularExpression] = {
        [#"\b\d{1,3}(\.\d{1,3}){3}\b"#,
         #"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"#,
         #"\b[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+\b"#]
            .compactMap { try? NSRegularExpression(pattern: $0) }
    }()

    public static func scrub(_ s: String) -> String {
        var out = s
        for re in patterns {
            out = re.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out),
                                              withTemplate: "[redacted]")
        }
        return out
    }
}
