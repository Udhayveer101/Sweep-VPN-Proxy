#if os(macOS)
import Foundation
import Security
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

    /// Gaming mode never rotates flows. Every MASQUE session is a new
    /// connection at Cloudflare and does not carry the inner TCP connections
    /// across, so each rotation reset every open game connection ("Connection
    /// reset" in Minecraft). Measured 2026-09-27 with the shipped usque: 4 of 7
    /// long TCP transfers cut with rotation on, 0 of 7 with it off. There used
    /// to be a "Rotate flows early" option here; it is gone so nobody can land
    /// on it by accident.

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
    /// The log is kept across runs so earlier sessions can be checked, and
    /// rolled to gamemode.log.1 once it passes this size.
    static let logLimit: UInt64 = 1 << 20
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

    public func start(onState: @escaping @Sendable (State) -> Void) {
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

        // The control file must exist before the script does: it polls for
        // the file and exits the moment it is gone. The log is appended, not
        // replaced; the monitor reads only what this run adds.
        rollLog()
        lock.lock()
        controlFile = workDir.appendingPathComponent(Self.controlPrefix + UUID().uuidString + ".control")
        let control = controlFile
        lock.unlock()
        FileManager.default.createFile(atPath: control.path, contents: nil)
        logOffset = (try? FileManager.default.attributesOfItem(atPath: logFile.path)[.size] as? UInt64) ?? 0
        state = .starting
        record(.info, "starting", "sni=\(sni)")

        // The routing table and utun need root. A Developer ID app cannot
        // install a privileged helper without a paid Network Extension
        // entitlement, so the admin prompt is the honest path: one password,
        // and the script owns its own teardown.
        // Both launch paths run the same root bootstrap (see rootBootstrap):
        // the bundle is user-writable, so root runs verified copies, never
        // the files in the bundle.
        let bootstrap = Self.rootBootstrap(team: Self.signingTeam())
        let bootstrapArgs = [script.path, usque.path, configFile.path,
                             control.path, logFile.path, sni]
        let command = (["/bin/bash", "-p", "-c", bootstrap, "gamemode-bootstrap"] + bootstrapArgs)
            .map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
            .joined(separator: " ")


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
                                arguments: ["-p", "-c", bootstrap, "gamemode-bootstrap"] + bootstrapArgs) {
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

    /// Once the tunnel is up the only lines that matter are a restart or a
    /// FATAL, and both are rare. Polling twice a second was for the start,
    /// where the user is watching a spinner; kept up for a whole session it is
    /// 170,000 wakeups a day to read nothing.
    static let runningPollInterval: DispatchTimeInterval = .seconds(2)

    private func relaxMonitor() {
        lock.lock()
        monitor?.schedule(deadline: .now() + Self.runningPollInterval,
                          repeating: Self.runningPollInterval, leeway: .milliseconds(500))
        lock.unlock()
    }

    /// The first thing that runs as root. gamemode.sh and usque sit in an app
    /// bundle the user can write to, so running them in place would hand root
    /// to anything that can write there. Instead: copy both into a fresh
    /// root-owned directory, check the copies carry our Developer ID
    /// signature, and run only the copies. Once copied, nothing unprivileged
    /// can change them, so the check cannot be raced.
    ///
    /// This text is compiled into the signed app, which is what makes it
    /// trustworthy where the script is not. `team` is nil for ad-hoc builds,
    /// which have no signature to check against.
    /// Arguments: script usque config control log sni.
    static func rootBootstrap(team: String?) -> String {
        let verify = team.map { team in
            """
            REQ='anchor apple generic and certificate leaf[subject.OU] = "\(team)"'
            for f in usque gamemode.sh; do
                /usr/bin/codesign --verify --strict -R="$REQ" "$D/$f" 2>/dev/null ||
                    fail "$f is not signed by team \(team); refusing to run it as root"
            done
            """
        } ?? ""
        return """
        set -u
        S="$1"; U="$2"; shift 2
        CONTROL="$2"; LOG="$3"
        fail() {
            [ -L "$LOG" ] || echo "$(date '+%H:%M:%S') gamemode: FATAL $*" >> "$LOG"
            rm -rf "${D:-}"; rm -f "$CONTROL"
            exit 1
        }
        D=$(/usr/bin/mktemp -d /private/var/run/sweep-gamemode.XXXXXX) || fail "no private directory"
        /usr/sbin/chown root:wheel "$D" && /bin/chmod 700 "$D" || fail "could not secure $D"
        /usr/bin/ditto "$S" "$D/gamemode.sh" && /usr/bin/ditto "$U" "$D/usque" || fail "could not copy the gaming mode payload"
        /usr/sbin/chown root:wheel "$D/gamemode.sh" "$D/usque" && /bin/chmod 500 "$D/gamemode.sh" "$D/usque" || fail "could not secure the payload"
        \(verify)
        exec /bin/bash -p "$D/gamemode.sh" "$D/usque" "$@"
        """
    }

    /// Our own Developer ID team, read from the running (already verified)
    /// code rather than from anything on disk.
    static func signingTeam() -> String? {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
        else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
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
                relaxMonitor()
                record(.info, "ready", line)
            case .fatal:
                teardown(reason: Self.reason(for: line))
            case .restarting:
                record(.error, "usqueExited", line)
            case nil:
                break
            }
        }
    }

    enum LogEvent: Equatable { case ready, restarting, fatal }

    static func classify(_ line: String) -> LogEvent? {
        // "HH:mm:ss app: ..." is our own echo of an event; re-reading it
        // would record it again, forever.
        if line.split(separator: " ", maxSplits: 2).dropFirst().first == "app:" { return nil }
        if line.contains("gamemode: ready") { return .ready }
        if line.contains("gamemode: FATAL") { return .fatal }
        // After "ready", usque dying is restarted with traffic held in the
        // tunnel; only a restart that keeps failing is FATAL.
        if line.contains("gamemode: usque exited; restarting") { return .restarting }
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
        if line.contains("usque would not restart") {
            return "The WARP tunnel kept stopping, so gaming mode turned itself off and put your normal routing back. Turn it on again to reconnect."
        }
        if line.contains("interface never came up") {
            return "The tunnel interface never appeared. Try again, or reconnect to the network."
        }
        return "Gaming mode stopped: \(line)"
    }

    private func record(_ level: LogEntry.Level, _ kind: String, _ detail: String) {
        EventLog.shared.record(phase: "gamemode", level: level, kind: kind, detail: detail)
        appendToLog("app: \(kind) \(detail)")
    }

    /// App-side events go into gamemode.log too, so one file tells the whole
    /// story of a session. The root script appends to the same file.
    private func appendToLog(_ text: String) {
        guard let data = "\(Self.logStamp.string(from: Date())) \(text)\n".data(using: .utf8) else { return }
        if !FileManager.default.fileExists(atPath: logFile.path) {
            try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: logFile.path, contents: nil)
        }
        guard let h = try? FileHandle(forWritingTo: logFile) else { return }
        defer { try? h.close() }
        _ = try? h.seekToEnd()
        try? h.write(contentsOf: data)
    }

    private static let logStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// Keep one previous generation once the log passes `logLimit`.
    func rollLog() {
        let fm = FileManager.default
        try? fm.createDirectory(at: workDir, withIntermediateDirectories: true)
        let size = (try? fm.attributesOfItem(atPath: logFile.path)[.size] as? UInt64) ?? 0
        if size > Self.logLimit {
            let old = workDir.appendingPathComponent("gamemode.log.1")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: logFile, to: old)
        }
        if !fm.fileExists(atPath: logFile.path) {
            fm.createFile(atPath: logFile.path, contents: nil)
        }
    }
}
#endif
