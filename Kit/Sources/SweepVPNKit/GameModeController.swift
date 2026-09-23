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
    /// one at once. `standby` used to mean "keep a warm session so a kill is a
    /// promotion instead of a rebuild", and it turned out to mean nothing: the
    /// standby is swept in the same sweep as the live flow, at whatever age it
    /// has reached, so promoting it hands the tunnel a dead session (measured
    /// 2026-09-20, 11 of 26 promotions already dead — see
    /// docs/measurements-2026-09-20.md). So `standby` now keeps no standby; it
    /// is the plain tunnel, reconnecting after each kill, which is what the
    /// numbers favour. The case name is kept because it is a stored setting.
    /// `rotate` retires each flow before it is old enough to be swept, and is
    /// the one mode that does park a warm session, because it has to rotate
    /// *into* one. It stays opt-in: ~1 in 20 new connections stalls in the swap
    /// window.
    public enum Disguise: String, Sendable, CaseIterable {
        case standby
        case rotate

        /// The ISP's sweep lands every 1-4 minutes, so 45s retired a healthy
        /// flow about twice as often as the threat needed. 90s (±20% jitter,
        /// applied in usque) still rotates well inside the sweep.
        ///
        /// Rotation stays opt-in, and `.standby` stays the default, because the
        /// swap window is expensive in a way the median hides. Measured
        /// 2026-09-20 over 18 minutes and 16 rotations (see
        /// docs/measurements-2026-09-20.md): median throughput was unchanged at
        /// 23 Mbit/s, but the tenth-percentile transfer fell from 19.95 Mbit/s
        /// to 1.76 Mbit/s. For a download that averages out. For a game it does
        /// not — a periodic collapse to 1.76 Mbit/s is exactly the interruption
        /// this mode exists to avoid. Do not reach for rotation when someone
        /// reports stutter; it is the cause, not the cure.
        var flowTTL: String { self == .rotate ? "90s" : "0" }

        public var title: String {
            switch self {
            case .standby: return "Reconnect on drops (recommended)"
            case .rotate:  return "Rotate flows early"
            }
        }
    }

    private let script: URL
    private let usque: URL
    /// Where the app's WARP registration lives - possibly inside the app's
    /// sandbox container, which root cannot read.
    private let sourceConfig: URL
    /// Our own copy, outside any container, plus the control and log files.
    private let workDir: URL
    private var configFile: URL { workDir.appendingPathComponent("config.json") }
    /// One name per run. A fixed name let a quick off-then-on recreate the file
    /// the previous root script was still polling for, so that script never
    /// exited and two of them fought over the routing table.
    private var controlFile: URL
    private static let controlPrefix = "gamemode-"
    private var logFile: URL { workDir.appendingPathComponent("gamemode.log") }
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

    init(script: URL, usque: URL, directory: URL, sni: String = "example.com",
         workDir: URL = GameModeController.defaultWorkDir) {
        self.script = script
        self.usque = usque
        self.sni = sni
        self.sourceConfig = directory.appendingPathComponent("config.json")
        self.workDir = workDir
        self.controlFile = workDir.appendingPathComponent(Self.controlPrefix + "idle.control")
    }

    /// Call once at launch. A script still running from before (the app
    /// crashed or was force-quit) is one nothing tracks: the toggle would read
    /// off while the Mac stayed routed. Stopping it lets its trap restore the
    /// network.
    public static func withdrawOrphanedRuns() {
        GameModeController(script: URL(fileURLWithPath: "/"), usque: URL(fileURLWithPath: "/"),
                           directory: URL(fileURLWithPath: "/")).withdrawStaleRuns()
    }

    /// Withdraw every control file, stopping any script a crashed or older run
    /// left behind (its EXIT trap restores routes and DNS). Returns whether
    /// there was one, so the caller can give its cleanup time to finish.
    @discardableResult
    func withdrawStaleRuns() -> Bool {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: workDir.path)) ?? []
        var found = false
        for name in names where name.hasSuffix(".control")
            && (name.hasPrefix(Self.controlPrefix) || name == "gamemode.control") {
            try? FileManager.default.removeItem(at: workDir.appendingPathComponent(name))
            found = true
        }
        return found
    }

    /// Deliberately not the app's container.
    ///
    /// The privileged half runs as root, and macOS denies even root access to
    /// another app's sandbox container. With the work files in there, usque
    /// could not read the registration and the script could not write its own
    /// log - so a failed run left an empty log and no way to see why.
    public static var defaultWorkDir: URL {
        SupportDirectory.base
            .appendingPathComponent("SweepVPN/gamemode", isDirectory: true)
    }

    /// Gaming mode needs the same WARP registration the proxy mode uses.
    public var isRegistered: Bool {
        FileManager.default.fileExists(atPath: sourceConfig.path)
    }

    /// Place the registration where the root process can read it. The app can
    /// read its own container; root cannot, so the app is the one that must
    /// carry it across.
    private func stageConfig() throws {
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: configFile.path) {
            try FileManager.default.removeItem(at: configFile)
        }
        try FileManager.default.copyItem(at: sourceConfig, to: configFile)
        // usque rewrites the config when it refreshes its token.
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configFile.path)
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

        // A script still running from a crash, or from an off a moment ago,
        // must finish restoring the network before this one changes it; it
        // polls once a second.
        let settle: TimeInterval = withdrawStaleRuns() ? 1.5 : 0

        do {
            try stageConfig()
        } catch {
            state = .failed("Could not prepare the WARP config: \(error.localizedDescription)")
            return
        }

        // Fresh log per run, and the control file must exist before the script
        // does: it polls for the file and exits the moment it is gone.
        try? FileManager.default.removeItem(at: logFile)
        FileManager.default.createFile(atPath: logFile.path, contents: nil)
        lock.lock()
        controlFile = workDir.appendingPathComponent(Self.controlPrefix + UUID().uuidString + ".control")
        let control = controlFile
        lock.unlock()
        FileManager.default.createFile(atPath: control.path, contents: nil)
        logOffset = 0
        state = .starting
        record(.info, "starting", "disguise=\(disguise.rawValue) sni=\(sni)")

        // The routing table and utun need root. A Developer ID app cannot
        // install a privileged helper without a paid Network Extension
        // entitlement, so the admin prompt is the honest path: one password,
        // and the script owns its own teardown.
        let command = [script.path, usque.path, configFile.path,
                       control.path, logFile.path, sni, disguise.flowTTL]
            .map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
            .joined(separator: " ")

        let scriptArgs = [usque.path, configFile.path, control.path,
                          logFile.path, sni, disguise.flowTTL]

        DispatchQueue.global().asyncAfter(deadline: .now() + settle) { [self] in
            lock.lock()
            let cancelled = stopped || controlFile != control
            lock.unlock()
            guard !cancelled else { return }
            // Preferred: the system's own authorization dialog, which offers
            // Touch ID where the Mac allows it. Anything other than the user
            // saying no falls through to the AppleScript prompt below, so this
            // can only improve on the old behaviour, never replace it.
            // Via /bin/bash -p, never the script path directly: the
            // authorization trampoline hands the child an elevated euid with
            // the real uid unchanged, and bash drops that euid on startup
            // unless -p says otherwise. Exec'ing the script itself therefore
            // ran the whole of gaming mode as the logged-in user, where every
            // route change silently no-ops and usque cannot create a utun.
            switch Elevator.run(tool: "/bin/bash",
                                arguments: ["-p", script.path] + scriptArgs) {
            case .launched:
                record(.info, "elevated", "system authorization")
                self.armMonitor(control)
                return
            case .cancelled:
                self.teardown(reason: "Gaming mode needs your permission to change routing.")
                return
            case .unavailable(let why):
                record(.info, "elevateFallback", why)
            }

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
            self.armMonitor(control)
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
        withdrawStaleRuns()
        record(.info, "stopped", "control withdrawn")
        state = .stopped
    }

    private func teardown(reason: String) {
        withdrawStaleRuns()
        lock.lock()
        monitor?.cancel()
        monitor = nil
        lock.unlock()
        record(.error, "failed", reason)
        state = .failed(reason)
    }

    /// The script is a root process we cannot inspect, so its log is the only
    /// channel. Polling it is enough: the interesting lines are rare.
    private func armMonitor(_ control: URL) {
        lock.lock()
        monitor?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in self?.pollLog() }
        monitor = timer
        lock.unlock()
        timer.resume()

        // The script gives up on its own after ~20s without a device. If it
        // never ran at all (the elevated shell died first), no line ever
        // comes, and "starting" would otherwise be permanent.
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.startTimeout) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let sameRun = self.controlFile == control && !self.stopped
            self.lock.unlock()
            guard sameRun else { return }
            self.pollLog()
            if self.state == .starting {
                self.teardown(reason: "Gaming mode did not start within \(Int(Self.startTimeout)) seconds. Try again.")
            }
        }
    }

    static let startTimeout: TimeInterval = 60

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
        // After "ready", usque dying ends the script and restores direct
        // routing; without this the app kept saying the Mac went through WARP.
        if line.contains("gamemode: usque exited") { return .fatal }
        if line.contains("Retiring MASQUE flow") { return .rotated }
        return nil
    }

    static func reason(for line: String) -> String {
        if line.contains("no default gateway") {
            return "No network connection, so gaming mode has nothing to tunnel over."
        }
        if line.contains("not running as root") {
            return "Gaming mode did not get administrator rights, so it could not change routing."
        }
        if line.contains("usque exited during setup") {
            return "The WARP tunnel would not start. Check Settings ▸ WARP setup."
        }
        if line.contains("usque exited; shutting down") {
            return "The WARP tunnel stopped, so gaming mode turned itself off and put your normal routing back. Turn it on again to reconnect."
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
