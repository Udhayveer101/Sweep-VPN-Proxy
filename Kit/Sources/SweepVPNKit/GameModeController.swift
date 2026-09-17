#if os(macOS)
import Foundation
import SweepVPNCore

/// Routes the whole Mac through WARP so games work — the proxy modes cannot.
///
/// `WarpController` exposes WARP as a loopback SOCKS port, which only apps that
/// honour a proxy will use. Games do not: they carry gameplay over UDP, which
/// this ISP drops, so they bypass the tunnel entirely. Gaming mode instead runs
/// usque's `nativetun` on a utun device and points the default route at it, so
/// every packet including UDP goes through the MASQUE session.
///
/// Deliberately isolated from `WarpController`: its own child process, its own
/// log, its own config copy and its own port-free path. The two are mutually
/// exclusive (see `VPNViewModel`), so neither can route over the other.
public final class GameModeController: @unchecked Sendable {

    public enum State: Equatable, Sendable {
        case stopped
        case starting
        case running
        case failed(String)

        public var isFailed: Bool { if case .failed = self { return true }; return false }
    }

    /// How aggressively to hide the ISP's flow kills.
    ///
    /// The network sweeps established TCP flows and tears down every long-lived
    /// one at once. `standby` keeps a warm session so a kill is replaced by a
    /// promotion instead of a rebuild. `rotate` additionally retires each flow
    /// before it is old enough to be swept — measured zero kills over 11
    /// rotations, but ~1 in 20 new connections stalls in the swap window, so it
    /// stays opt-in.
    public enum Disguise: String, Sendable, CaseIterable {
        case standby
        case rotate

        var flowTTL: String { self == .rotate ? "45s" : "0" }

        public var title: String {
            switch self {
            case .standby: return "Standby (recommended)"
            case .rotate:  return "Standby + rotate flows"
            }
        }
    }

    private let script: URL
    private let usque: URL
    private let configFile: URL
    private let controlFile: URL
    private let logFile: URL
    public let sni: String

    private let lock = NSLock()
    private var monitor: DispatchSourceTimer?
    private var logOffset: UInt64 = 0
    private var stopped = true

    private(set) public var state: State = .stopped {
        didSet { if state != oldValue { onState?(state) } }
    }
    private var onState: (@Sendable (State) -> Void)?

    /// `nil` when the app was built without usque or the helper script.
    public static func bundled(bundle: Bundle = .main) -> GameModeController? {
        guard let usque = WarpController.bundledExecutable(bundle: bundle) else { return nil }
        let script = bundle.bundleURL.appendingPathComponent("Contents/Resources/warp/gamemode.sh")
        guard FileManager.default.fileExists(atPath: script.path) else { return nil }
        return GameModeController(script: script, usque: usque,
                                  directory: WarpController.defaultDirectory)
    }

    init(script: URL, usque: URL, directory: URL, sni: String = "example.com") {
        self.script = script
        self.usque = usque
        self.sni = sni
        self.configFile = directory.appendingPathComponent("config.json")
        self.controlFile = directory.appendingPathComponent("gamemode.control")
        self.logFile = directory.appendingPathComponent("gamemode.log")
    }

    /// Gaming mode needs the same WARP registration the proxy mode uses.
    public var isRegistered: Bool {
        FileManager.default.fileExists(atPath: configFile.path)
    }

    public func start(disguise: Disguise = .standby,
                      onState: @escaping @Sendable (State) -> Void) {
        lock.lock()
        self.onState = onState
        stopped = false
        lock.unlock()

        guard isRegistered else {
            state = .failed("WARP is not set up yet. Open Settings ▸ WARP setup and press Register.")
            return
        }

        // Fresh log per run, and the control file must exist before the script
        // does: it polls for the file and exits the moment it is gone.
        try? FileManager.default.removeItem(at: logFile)
        FileManager.default.createFile(atPath: logFile.path, contents: nil)
        FileManager.default.createFile(atPath: controlFile.path, contents: nil)
        logOffset = 0
        state = .starting
        record(.info, "starting", "disguise=\(disguise.rawValue) sni=\(sni)")

        // The routing table and utun need root. A Developer ID app cannot
        // install a privileged helper without a paid Network Extension
        // entitlement, so the admin prompt is the honest path: one password,
        // and the script owns its own teardown.
        let command = [script.path, usque.path, configFile.path,
                       controlFile.path, logFile.path, sni, disguise.flowTTL]
            .map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
            .joined(separator: " ")

        DispatchQueue.global().async { [self] in
            let osa = Process()
            osa.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            osa.arguments = ["-e",
                "do shell script \"\(command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")) > /dev/null 2>&1 &\" with administrator privileges"]
            do {
                try osa.run()
                osa.waitUntilExit()
                if osa.terminationStatus != 0 {
                    // -128 is the user dismissing the password prompt.
                    self.teardown(reason: osa.terminationStatus == 1
                                  ? "Gaming mode needs your admin password to change routing."
                                  : "Could not start gaming mode (status \(osa.terminationStatus)).")
                    return
                }
            } catch {
                self.teardown(reason: "Could not start gaming mode: \(error.localizedDescription)")
                return
            }
            self.armMonitor()
        }
    }

    public func stop() {
        lock.lock()
        stopped = true
        monitor?.cancel()
        monitor = nil
        lock.unlock()

        // Withdrawing the control file is the stop signal: the script is root
        // and we are not, so we cannot signal it directly. Its EXIT trap then
        // restores routes and DNS.
        try? FileManager.default.removeItem(at: controlFile)
        record(.info, "stopped", "control withdrawn")
        state = .stopped
    }

    private func teardown(reason: String) {
        try? FileManager.default.removeItem(at: controlFile)
        lock.lock()
        monitor?.cancel()
        monitor = nil
        lock.unlock()
        record(.error, "failed", reason)
        state = .failed(reason)
    }

    /// The script is a root process we cannot inspect, so its log is the only
    /// channel. Polling it is enough: the interesting lines are rare.
    private func armMonitor() {
        lock.lock()
        monitor?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in self?.pollLog() }
        monitor = timer
        lock.unlock()
        timer.resume()
    }

    private func pollLog() {
        lock.lock()
        let done = stopped
        lock.unlock()
        guard !done else { return }

        guard let handle = try? FileHandle(forReadingFrom: logFile) else { return }
        defer { try? handle.close() }
        try? handle.seek(toOffset: logOffset)
        guard let data = try? handle.readToEnd(), !data.isEmpty,
              let text = String(data: data, encoding: .utf8) else { return }
        logOffset += UInt64(data.count)
        ingest(log: text)
    }

    func ingest(log text: String) {
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            switch Self.classify(line) {
            case .ready:
                state = .running
                record(.info, "ready", line)
            case .fatal:
                teardown(reason: Self.reason(for: line))
            case .rotated:
                record(.info, "rotated", line)
            case nil:
                break
            }
        }
    }

    enum LogEvent: Equatable { case ready, rotated, fatal }

    static func classify(_ line: String) -> LogEvent? {
        if line.contains("gamemode: ready") { return .ready }
        if line.contains("gamemode: FATAL") { return .fatal }
        if line.contains("Retiring MASQUE flow") { return .rotated }
        return nil
    }

    static func reason(for line: String) -> String {
        if line.contains("no default gateway") {
            return "No network connection, so gaming mode has nothing to tunnel over."
        }
        if line.contains("usque exited during setup") {
            return "The WARP tunnel would not start. Check Settings ▸ WARP setup."
        }
        if line.contains("interface never came up") {
            return "The tunnel interface never appeared. Try again, or reconnect to the network."
        }
        return "Gaming mode stopped: \(line)"
    }

    private func record(_ level: LogEntry.Level, _ kind: String, _ detail: String) {
        EventLog.shared.record(phase: "gamemode", level: level, kind: kind, detail: detail)
    }
}
#endif
