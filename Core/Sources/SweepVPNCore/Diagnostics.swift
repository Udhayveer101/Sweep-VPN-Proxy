import Foundation

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

public final class Diagnostics: @unchecked Sendable {
    private let capacity: Int
    private var buffer: [DiagnosticEvent] = []
    private let lock = NSLock()   // ponytail: one lock, ring buffer is not hot

    public init(capacity: Int = 512) {
        self.capacity = capacity
        buffer.reserveCapacity(capacity)
    }

    public func record(_ kind: String, _ detail: String = "", at: Date = Date()) {
        let event = DiagnosticEvent(at: at, kind: kind, detail: detail)
        lock.lock(); defer { lock.unlock() }
        buffer.append(event)
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
    }

    public func snapshot() -> [DiagnosticEvent] {
        lock.lock(); defer { lock.unlock() }
        return buffer
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
