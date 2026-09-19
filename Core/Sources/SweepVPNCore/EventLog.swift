import Foundation

/// A step in the log, as one line of the shared journal.
///
/// The fields exist to answer the question the old log could not: *where in the
/// sequence did this stop*. `run` groups every line produced by one connect
/// attempt, `elapsedMs` says how long that attempt had been going when the line
/// was written, and `process` says which side wrote it — the app and the tunnel
/// extension are separate processes and only their interleaving shows a stall.
public struct LogEntry: Codable, Sendable, Equatable, Identifiable {
    public enum Level: String, Codable, Sendable, CaseIterable {
        case debug, info, warn, error
    }

    public var id: String
    public var at: Date
    /// "app", "tunnel" or "filter".
    public var process: String
    /// The stage this belongs to: "connect", "relay", "profile", "worker",
    /// "tunnel", "ipc". Used to group and filter, never parsed for meaning.
    public var phase: String
    public var level: Level
    public var kind: String
    public var detail: String
    /// Milliseconds since this run began. Nil when no run was open.
    public var elapsedMs: Int?
    public var run: String

    public init(id: String = UUID().uuidString, at: Date = Date(), process: String,
                phase: String, level: Level, kind: String, detail: String,
                elapsedMs: Int?, run: String) {
        self.id = id
        self.at = at
        self.process = process
        self.phase = phase
        self.level = level
        self.kind = kind
        self.detail = Diagnostics.scrub(detail)
        self.elapsedMs = elapsedMs
        self.run = run
    }
}

/// Append-only journal in the shared app group, written by every Sweep process
/// and readable at any time.
///
/// # Why a file and not the diagnostic ring
///
/// `Diagnostics` keeps one ring per process, in memory, and it only ever
/// escaped as a 40-line trail stapled to a *failure*. That left the two cases
/// that matter most invisible: a tunnel that hangs in "connecting" produces no
/// failure and so produced no readable log at all, and a tunnel that dies takes
/// its ring with it. A file in the group container is the only place both
/// processes can write and the app can still read afterwards.
///
/// # Concurrency
///
/// Each line is a single append to a descriptor in `O_APPEND` mode, which the
/// kernel will not interleave with another process's append for a write this
/// small. That is the whole locking story across processes.
/// ponytail: O_APPEND line atomicity, move to a lock file if lines ever exceed a page.
public final class EventLog: @unchecked Sendable {
    public static let shared = EventLog(appGroup: AppGroupID.resolved)

    /// Trimmed back to `trimTo` once it grows past this.
    private static let maxBytes = 4 * 1024 * 1024
    private static let trimTo = 2 * 1024 * 1024

    /// How often the journal may be measured for trimming. Every append used to
    /// stat the file, and past the cap every append read the whole 4MB in and
    /// wrote 2MB back — inside an iOS packet-tunnel extension with a 32MB Go
    /// memory limit and a 50MB jetsam ceiling. Under a reconnect storm that was
    /// the most expensive thing the tunnel did.
    private static let trimCheckInterval: TimeInterval = 60

    private let lock = NSLock()
    private let directory: URL?
    private let runKeyStore: UserDefaults?
    private let processName: String
    /// Appends happen here, not on the caller's thread. usque's logging
    /// goroutine and the extension's start path both call `record` directly;
    /// neither should ever wait on the filesystem.
    private let writeQueue = DispatchQueue(label: "sweep.eventlog", qos: .utility)
    private var lastTrimCheck: Date = .distantPast
    /// Reported once rather than every line, so a broken journal is visible in
    /// the console without becoming its own storm.
    private var reportedWriteFailure = false

    public var fileURL: URL? { directory?.appendingPathComponent("events.jsonl") }

    public init(appGroup: String) {
        self.directory = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        self.runKeyStore = UserDefaults(suiteName: appGroup)
        let name = ProcessInfo.processInfo.processName.lowercased()
        // The extension's process name carries the target name, which is the
        // only reliable way for a line to say which side wrote it.
        if name.contains("tunnel") { self.processName = "tunnel" }
        else if name.contains("filter") { self.processName = "filter" }
        else { self.processName = "app" }
    }

    /// Test seam: a journal in a directory of the caller's choosing.
    public init(directory: URL?, defaults: UserDefaults?, processName: String) {
        self.directory = directory
        self.runKeyStore = defaults
        self.processName = processName
    }

    // MARK: - Runs

    private static let runIDKey = "sweep.log.runID"
    private static let runStartKey = "sweep.log.runStartedAt"

    /// Opens a new run and returns its id. Called by the app when the user asks
    /// for a connect, so every line either side writes afterwards is attributed
    /// to that attempt.
    @discardableResult
    public func beginRun(_ label: String) -> String {
        let id = String(UUID().uuidString.prefix(8))
        runKeyStore?.set(id, forKey: Self.runIDKey)
        runKeyStore?.set(Date().timeIntervalSince1970, forKey: Self.runStartKey)
        record(phase: "connect", level: .info, kind: "runStarted", detail: label)
        return id
    }

    private var currentRun: String { runKeyStore?.string(forKey: Self.runIDKey) ?? "—" }

    private var runStartedAt: Date? {
        let raw = runKeyStore?.double(forKey: Self.runStartKey) ?? 0
        return raw > 0 ? Date(timeIntervalSince1970: raw) : nil
    }

    // MARK: - Writing

    public func record(phase: String, level: LogEntry.Level = .info,
                       kind: String, detail: String = "") {
        let elapsed = runStartedAt.map { Int(Date().timeIntervalSince($0) * 1000) }
        let entry = LogEntry(process: processName, phase: phase, level: level,
                             kind: kind, detail: detail, elapsedMs: elapsed,
                             run: currentRun)
        writeQueue.async { [self] in append(entry) }
    }

    /// Waits for every queued line to reach the file. Readers call this first,
    /// so the Connection Log still shows a line the instant it is recorded even
    /// though the write itself is off the hot path.
    public func flush() { writeQueue.sync {} }

    private func append(_ entry: LogEntry) {
        guard let url = fileURL,
              var data = try? JSONEncoder.logEncoder.encode(entry) else { return }
        data.append(0x0A)
        lock.lock(); defer { lock.unlock() }
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil)
        }
        do {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            // O_APPEND is what makes this safe against the other process; seeking
            // to a cached end offset would let two writers land on the same
            // bytes. It is also why the handle is not cached: a trim in either
            // process replaces the inode, and a cached descriptor would go on
            // writing to the file nobody can read any more.
            guard fcntl(handle.fileDescriptor, F_SETFL, O_APPEND) != -1 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try handle.write(contentsOf: data)
            reportedWriteFailure = false
        } catch {
            // A diagnostic that fails silently is worse than no diagnostic: the
            // user sends a journal with the interesting minute simply missing.
            if !reportedWriteFailure {
                reportedWriteFailure = true
                FileHandle.standardError.write(
                    Data("sweep: event log unwritable at \(url.path): \(error)\n".utf8))
            }
            return
        }
        trimIfNeeded(url)
    }

    /// Drops the oldest whole lines once the journal outgrows its cap. Whole
    /// lines, because a half-line is not decodable and would poison the reader.
    ///
    /// Measured at most once a `trimCheckInterval`, and it reads only the tail
    /// it intends to keep rather than the whole file.
    private func trimIfNeeded(_ url: URL) {
        let now = Date()
        guard now.timeIntervalSince(lastTrimCheck) >= Self.trimCheckInterval else { return }
        lastTrimCheck = now
        guard let size = try? FileManager.default
                .attributesOfItem(atPath: url.path)[.size] as? Int,
              size > Self.maxBytes,
              let reader = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? reader.close() }
        guard (try? reader.seek(toOffset: UInt64(size - Self.trimTo))) != nil,
              let keep = try? reader.readToEnd(),
              let newlineIndex = keep.firstIndex(of: 0x0A) else { return }
        try? Data(keep[keep.index(after: newlineIndex)...]).write(to: url, options: .atomic)
    }

    // MARK: - Reading

    /// The whole journal, oldest first. Undecodable lines are skipped rather
    /// than failing the read — a torn tail must not hide the 2,000 good lines
    /// above it.
    public func entries() -> [LogEntry] {
        flush()
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return [] }
        return data.split(separator: 0x0A).compactMap {
            try? JSONDecoder.logDecoder.decode(LogEntry.self, from: Data($0))
        }
    }

    public func clear() {
        flush()   // else a line already queued lands after the truncate
        lock.lock(); defer { lock.unlock() }
        guard let url = fileURL else { return }
        try? Data().write(to: url, options: .atomic)
    }

    /// Plain text, oldest first — what the Copy button hands over.
    public func export() -> String {
        entries().map(Self.line).joined(separator: "\n")
    }

    public static func line(_ e: LogEntry) -> String {
        let stamp = ISO8601DateFormatter().string(from: e.at)
        let elapsed = e.elapsedMs.map { String(format: "+%6.2fs", Double($0) / 1000) } ?? "        "
        let body = e.detail.isEmpty ? e.kind : "\(e.kind): \(e.detail)"
        return "\(stamp) \(elapsed) [\(e.run)] \(e.process)/\(e.phase) \(e.level.rawValue.uppercased()) \(body)"
    }
}

extension JSONEncoder {
    static let logEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970
        return e
    }()
}

extension JSONDecoder {
    static let logDecoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }()
}
