#if os(macOS)
import Foundation
import SweepVPNCore

/// Runs usque (Cloudflare WARP over MASQUE) as a child of the app and exposes
/// it as a loopback SOCKS5 port — the same shape as `TorController`.
///
/// The MASQUE session is HTTP/2 over TLS to Cloudflare with a neutral SNI
/// (default example.com). The gateway filters on SNI and cannot see inside the
/// TLS, so the connection passes where WireGuard, OpenVPN and Tor do not
/// (measured 2026-09-11, see memory sweep_vpn_isp_block). No packet-tunnel
/// involvement: only apps pointed at the local proxy use it.
public final class WarpController: @unchecked Sendable {

    public enum State: Equatable, Sendable {
        case stopped
        case starting
        case running                 // SOCKS listener up; usque dials on demand
        case failed(String)

        public var isFailed: Bool { if case .failed = self { return true }; return false }
    }

    public let socksPort: Int
    public let sni: String
    let configFile: URL
    private let executable: URL

    private var process: Process?
    private let lock = NSLock()
    private var onState: (@Sendable (State) -> Void)?
    private var stallTimer: DispatchSourceTimer?
    private var recoveryTimer: DispatchSourceTimer?
    private var lastRestart: Date = .distantPast
    private var restarting = false
    private var stopped = false
    private var restartStreak = StartBackoff()
    /// Partial line left over from the last `availableData` chunk. Without it a
    /// log line split across a read boundary is classified as two fragments and
    /// the event in it — a loss, a reconnect — is simply never seen.
    private var logTail = ""
    private(set) public var state: State = .stopped {
        didSet { if state != oldValue { onState?(state) } }
    }

    /// `nil` when the app was built without usque (see Tools/bundle-tor.sh).
    public static func bundledExecutable(bundle: Bundle = .main) -> URL? {
        let url = bundle.bundleURL.appendingPathComponent("Contents/Resources/warp/usque")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// Application Support. The app was sandboxed when WARP shipped, so a
    /// registration may still sit in the old container; prefer it rather than
    /// making the user register again.
    public static var defaultDirectory: URL {
        let plain = SupportDirectory.base
            .appendingPathComponent("SweepVPN/warp", isDirectory: true)
        if FileManager.default.fileExists(atPath: plain.appendingPathComponent("config.json").path) {
            return plain
        }
        let container = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Containers/com.sweep.vpn.mac/Data/Library/Application Support/SweepVPN/warp",
                                    isDirectory: true)
        return FileManager.default.fileExists(atPath: container.appendingPathComponent("config.json").path)
            ? container : plain
    }

    public convenience init?(socksPort: Int = 1081, sni: String = "example.com",
                             bundle: Bundle = .main) {
        guard let exe = Self.bundledExecutable(bundle: bundle) else { return nil }
        self.init(executable: exe, socksPort: socksPort, sni: sni, directory: Self.defaultDirectory)
    }

    init(executable: URL, socksPort: Int, sni: String, directory: URL) {
        self.executable = executable
        self.socksPort = socksPort
        self.sni = sni
        self.configFile = directory.appendingPathComponent("config.json")
    }

    /// usque's default in-tunnel resolver list contains two IPv6 Quad9 servers,
    /// and IPv6 does not route inside this MASQUE session: those lookups stall
    /// for the 2s DNS deadline and the stuck in-tunnel UDP eventually takes the
    /// whole session down ("Tunnel connection lost: read: operation timed out"),
    /// after which every SOCKS dial fails until the idle reconnect. Pinning the
    /// IPv4 Cloudflare pair keeps lookups on a path that exists (measured
    /// 2026-09-12: 0/20 parallel fetches succeeded on the defaults, 20/20 here).
    /// `--always-reconnect`: without it usque parks after every tunnel loss
    /// ("Tunnel idle. Waiting for outbound activity"), and the packet that wakes
    /// it is *read off the TUN device and dropped* before the ~1s redial. That
    /// packet is normally the DNS query, and the resolver sends one datagram per
    /// server with no retry, so the first request after any loss — link drop,
    /// sleep/wake, a fresh start — dies as `lookup ...: i/o timeout`. Measured
    /// 2026-09-13 on a cold proxy: 12s failure or a 5s stall without the flag,
    /// 0.07-0.14s with it. `--dns-timeout` then covers a query that still lands
    /// inside a redial window.
    /// `-k 5s` (patched usque, api/masque.go): the path kills the MASQUE TCP
    /// flow every 1-4 min whatever we send (measured 2026-09-14, also on the
    /// original flags). Stock usque only wires keepalive into QUIC, so over
    /// HTTP/2 a dead flow went unnoticed for the ~20-25s kernel retransmit
    /// timeout and every lookup failed. HTTP/2 PINGs now catch it in <=8s, and
    /// the patched resolver re-asks every 1.5s, so a 15s DNS budget spans
    /// detection plus the ~3s redial instead of failing inside it.
    /// Deliberately *not* `--hot-standby`, which gaming mode does pass.
    ///
    /// The theory was good — a warm second session turns a swept flow into a
    /// promotion instead of a rebuild — but it did not survive measurement.
    /// Run head to head on 2026-09-20, both tunnels up at once so they saw the
    /// same network, 14 minutes each through Tools/soak.sh: with standby,
    /// median 19.77 Mbit/s and 1 failed transfer, longest unbroken 332s;
    /// without, median 19.34 Mbit/s and 0 failed, longest unbroken 535s. A wash
    /// on throughput, and if anything worse on the two numbers that matter.
    ///
    /// So it stays off here. A standby is a second long-lived TCP flow to the
    /// same endpoint, on the network that sweeps long-lived TCP flows, and that
    /// is not a cost worth paying for an effect nobody can measure. Gaming mode
    /// keeps it because rotation needs a warm session to rotate *into*.
    /// Re-measure before changing this, don't reason about it.
    var arguments: [String] {
        ["-c", configFile.path, "socks",
         "-s", sni, "--http2",
         "--always-reconnect", "-k", "5s", "--dns-timeout", "15s",
         "-d", "1.1.1.1", "-d", "1.0.0.1",
         "-b", "127.0.0.1", "-p", String(socksPort)]
    }

    public func start(onState: @escaping @Sendable (State) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        self.onState = onState
        stopped = false
        guard process == nil else { return }

        let dir = configFile.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        guard FileManager.default.fileExists(atPath: configFile.path) else {
            state = .failed("WARP is not set up yet. Open Settings ▸ WARP setup and press Register.")
            record(.error, "noConfig", configFile.path)
            return
        }

        let p = Process()
        p.executableURL = executable
        p.arguments = arguments
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty, let text = String(data: chunk, encoding: .utf8) else { return }
            self?.ingest(log: text)
        }
        p.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.lock.lock()
            let wasOurs = self.process === proc
            if wasOurs { self.process = nil }
            self.lock.unlock()
            guard wasOurs else { return }            // stop() already reported
            self.record(.warn, "exited", "status \(proc.terminationStatus)")
            if case .failed = self.state { return }  // keep the parsed reason
            self.state = .failed("WARP exited unexpectedly (status \(proc.terminationStatus)).")
        }

        do {
            try p.run()
            process = p
            state = .starting
            record(.info, "starting", "sni=\(sni) port=\(socksPort)")
            armStallWatchdog()
        } catch {
            state = .failed("Could not launch WARP: \(error.localizedDescription)")
        }
    }

    public func stop() {
        lock.lock()
        let p = process
        process = nil
        stopped = true
        stallTimer?.cancel()
        stallTimer = nil
        recoveryTimer?.cancel()
        recoveryTimer = nil
        logTail = ""
        lock.unlock()
        p?.terminate()
        if p != nil { record(.info, "stopped", "asked to stop") }
        state = .stopped
    }

    /// usque prints the listener line almost immediately; if it has not in 30s
    /// something is wrong (port taken, bad config) and the UI should say so.
    private func armStallWatchdog(seconds: Int = 30) {
        stallTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .seconds(seconds))
        timer.setEventHandler { [weak self] in
            guard let self, self.state == .starting else { return }
            self.record(.error, "stalled", "no listener after \(seconds)s")
            self.stop()
            self.state = .failed("WARP did not start within \(seconds) seconds.")
        }
        timer.resume()
        stallTimer = timer
    }

    /// Lines from usque 2026-09 (see WarpControllerTests for real samples).
    ///
    /// `availableData` splits wherever the pipe buffer happened to end, not on
    /// newlines, so the trailing fragment is held back and prepended to the next
    /// chunk instead of being classified as a line of its own.
    func ingest(log text: String) {
        lock.lock()
        let buffered = logTail + text
        var lines = buffered.components(separatedBy: .newlines)
        logTail = buffered.hasSuffix("\n") ? "" : (lines.popLast() ?? "")
        lock.unlock()

        for line in lines where !line.isEmpty {
            switch Self.classify(line) {
            case .listening:
                lock.lock(); stallTimer?.cancel(); stallTimer = nil; lock.unlock()
                state = .running
                record(.info, "listening", line)
            case .connected:
                // usque rebuilt the session by itself: whatever we were waiting
                // on healed, so stand the wedge deadline down.
                noteRecovered()
                record(.info, "connected", line)
            // A loss is usque telling us it is already reconnecting, not a fault
            // to act on. Both it and an outright error only start the clock; the
            // wedge is the clock running out, handled in armRecoveryDeadline.
            case .lost:
                record(.info, "lost", line)
                armRecoveryDeadline(line)
            case .error:
                record(.warn, "log", line)
                armRecoveryDeadline(line)
            case .connectionError:
                // One client's failure. Log it and leave the tunnel alone.
                record(.warn, "clientLog", line)
            case nil:
                break
            }
        }
    }

    /// usque heals its own session losses: `masque-closed-pipe.patch` ends a
    /// session whose HTTP/2 pipe died under a write, and `--always-reconnect`
    /// rebuilds it in about a second.
    ///
    /// Until now this supervisor relaunched the whole child process on the very
    /// first write error, so that cheap in-process reconnect was pre-empted by a
    /// cold restart — terminate, wait, reload the config, redo the TLS handshake,
    /// open a new listener — and for all of it the SOCKS port was *gone*, so
    /// every app connection failed outright. On a path that sweeps long-lived
    /// flows every 1-4 minutes that fired every 1-4 minutes. It is the regression
    /// testers felt from v1.3.0 (see docs/research-warp-stability-2026-09.md).
    ///
    /// So the supervisor now only acts when usque has *failed* to heal. A failure
    /// arms a deadline; a "Connected to MASQUE server" line disarms it; only an
    /// expired deadline is a wedge. That still catches the 2026-09-13 case — a
    /// pipe closed underneath a parked read pump, where usque logs
    /// "continuing..." forever and never reconnects — because in that case the
    /// reconnect line never comes.
    static let recoveryGrace: TimeInterval = 15
    static let restartFloor: TimeInterval = 20

    /// Start the clock on a failure line. Returns `true` if this call armed the
    /// deadline (bookkeeping only, so it stays testable); `now` is injectable
    /// for the same reason.
    @discardableResult
    func noteFailure(_ line: String, now: Date = Date()) -> Bool {
        lock.lock()
        guard !restarting, process != nil, recoveryTimer == nil,
              now.timeIntervalSince(lastRestart) >= Self.restartFloor else {
            lock.unlock(); return false
        }
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + Self.recoveryGrace)
        timer.setEventHandler { [weak self] in self?.recoveryDeadlineExpired(line) }
        recoveryTimer = timer
        lock.unlock()
        timer.resume()
        return true
    }

    /// usque reconnected on its own — the common case, and the one that must
    /// cost nothing.
    func noteRecovered() {
        lock.lock()
        let timer = recoveryTimer
        recoveryTimer = nil
        restartStreak = restartStreak.recordingSuccess()
        lock.unlock()
        timer?.cancel()
    }

    /// `true` when a failure is currently being waited on. Tests read it.
    var isAwaitingRecovery: Bool {
        lock.lock(); defer { lock.unlock() }
        return recoveryTimer != nil
    }

    private func armRecoveryDeadline(_ line: String) {
        guard noteFailure(line) else { return }
        record(.info, "watching", "no reconnect within \(Int(Self.recoveryGrace))s is a wedge")
    }

    private func recoveryDeadlineExpired(_ line: String) {
        lock.lock()
        recoveryTimer = nil
        guard !restarting, process != nil, !stopped else { lock.unlock(); return }
        restarting = true
        lastRestart = Date()
        restartStreak = restartStreak.recordingFailure()
        let delay = restartStreak.delay()
        lock.unlock()
        restartWedgedTunnel(line, after: delay)
    }

    /// Tests need a controller that believes a child is running without one —
    /// the state a real relaunch lands in.
    func pretendRunningForTests() {
        lock.lock(); defer { lock.unlock() }
        process = Process()
        restarting = false
    }

    /// Relaunch, after `delay`. usque failing to reconnect usually means the
    /// path is down, not that the child is sick, so repeated restarts back off
    /// (StartBackoff: 0, 2, 5, 15, 30, 60, 120s) rather than respawning every
    /// 20 seconds forever.
    private func restartWedgedTunnel(_ line: String, after delay: TimeInterval = 0) {
        record(.warn, "restarting",
               "no reconnect within \(Int(Self.recoveryGrace))s after: \(line)"
               + (delay > 0 ? " (waiting \(Int(delay))s)" : ""))
        DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [self] in
            lock.lock()
            let doomed = process
            process = nil
            stallTimer?.cancel()
            stallTimer = nil
            let callback = onState
            lock.unlock()

            doomed?.terminationHandler = nil          // this exit is ours, not a failure
            doomed?.terminate()
            doomed?.waitUntilExit()

            lock.lock()
            restarting = false
            let abandoned = stopped                   // stop() won the race
            lock.unlock()
            guard !abandoned, let callback else { return }
            start(onState: callback)
        }
    }

    private func record(_ level: LogEntry.Level, _ kind: String, _ detail: String) {
        EventLog.shared.record(phase: "warp", level: level, kind: kind, detail: detail)
    }
}

#endif

import Foundation

extension WarpController {
    enum LogEvent: Equatable {
        case listening, connected, lost
        /// The MASQUE session itself is in trouble, so usque owes us a
        /// reconnect and the wedge deadline means something.
        case error
        /// A failure that belongs to one SOCKS client — a dial, a DNS answer, a
        /// malformed datagram. Worth logging, never worth supervising.
        case connectionError
    }

    /// The only failures usque prints that are about the *session*.
    ///
    /// 2026-09-20: `SOCKS TCP handle from 127.0.0.1:63517 failed: dial: lookup
    /// ...: no such host` armed the wedge deadline. That is one client asking
    /// for a name that does not exist, over a tunnel that was working and was
    /// never lost — so no "Connected to MASQUE server" line could ever follow
    /// to disarm it, and 15s later the supervisor restarted a healthy tunnel
    /// and took the SOCKS listener down with it. Every per-connection failure
    /// has that shape: nothing reconnects, because nothing was disconnected.
    ///
    /// Matching on the session lines by name rather than excluding client lines
    /// by name is deliberate. usque logs a bare `log.Println(err)` for a bad
    /// SOCKS datagram (internal/socks5.go), so the text of a client failure is
    /// not something a deny-list can enumerate.
    static let sessionFaultPhrases = [
        "Failed to connect tunnel",          // dial half of MaintainTunnel's loop
        "Error writing to IP connection",    // the 2026-09-13 wedge: "continuing..." forever
        "Error reading from IP connection",
        "Failed to read from TUN device",
    ]

    /// Lines from usque 2026-09 (see WarpControllerTests for real samples).
    /// Shared by the macOS child-process supervisor and the iOS extension.
    static func classify(_ line: String) -> LogEvent? {
        if line.contains("SOCKS proxy listening on") { return .listening }
        if line.contains("Connected to MASQUE server") { return .connected }
        if line.contains("Tunnel connection lost") { return .lost }
        if sessionFaultPhrases.contains(where: line.contains) { return .error }
        let l = line.lowercased()
        if l.contains("failed") || l.contains("error") { return .connectionError }
        return nil
    }
}

/// The one-time WARP setup, done from the app instead of a terminal. WARP needs
/// no Cloudflare account or API key: registering creates a free, anonymous
/// device and writes its keys to `config.json`. A WARP+ license key and a Zero
/// Trust team token are both optional extras on top of that.
public enum WarpRegistration {

    public struct Failure: LocalizedError, Equatable {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// A config.json with a device private key. The file alone is not enough:
    /// iOS builds before 1.3.0 (4) saved one with every field blank.
    public static func isRegistered(directory: URL = WarpController.defaultDirectory) -> Bool {
        struct Keys: Decodable { let private_key: String? }
        guard let data = try? Data(contentsOf: directory.appendingPathComponent("config.json")),
              let keys = try? JSONDecoder().decode(Keys.self, from: data) else { return false }
        return !(keys.private_key ?? "").isEmpty
    }

    /// `xxxxxxxx-xxxxxxxx-xxxxxxxx`, the format usque's `account set` documents.
    public static func isValidLicenseKey(_ key: String) -> Bool {
        key.range(of: #"^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$"#, options: .regularExpression) != nil
    }

    static func validated(licenseKey: String) throws -> String {
        let key = licenseKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !key.isEmpty, !isValidLicenseKey(key) {
            throw Failure(message: "That license key does not look right. It should be three groups of 8 letters or digits, like ab12cd34-ef56gh78-ij90kl12.")
        }
        return key
    }
}

#if os(macOS)
extension WarpRegistration {
    static func registerArguments(configFile: URL, teamToken: String) -> [String] {
        var args = ["-c", configFile.path, "register", "--accept-tos", "-n", "Sweep VPN"]
        if !teamToken.isEmpty { args += ["--jwt", teamToken] }
        return args
    }

    static func licenseArguments(configFile: URL, key: String) -> [String] {
        ["-c", configFile.path, "account", "set", key]
    }

    /// Registers this Mac, then binds the license key if one was given. Only
    /// call after the user has accepted Cloudflare's terms: `--accept-tos`
    /// accepts them on their behalf. A failed license leaves the (working, free)
    /// registration in place and reports the license error.
    public static func register(licenseKey: String = "", teamToken: String = "",
                                executable: URL? = WarpController.bundledExecutable(),
                                directory: URL = WarpController.defaultDirectory) async throws {
        guard let executable else {
            throw Failure(message: "This build has no bundled usque, so WARP cannot be set up. Rebuild with `make install-macos`.")
        }
        let key = try validated(licenseKey: licenseKey)
        let token = teamToken.trimmingCharacters(in: .whitespacesAndNewlines)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let configFile = directory.appendingPathComponent("config.json")
        if !isRegistered(directory: directory) {
            try await run(executable, registerArguments(configFile: configFile, teamToken: token),
                          what: "Registration")
            guard isRegistered(directory: directory) else {
                throw Failure(message: "Registration finished but no WARP configuration was saved. Try again.")
            }
            // usque writes 0644; the file holds the device's private key.
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configFile.path)
            EventLog.shared.record(phase: "warp", kind: "registered", detail: token.isEmpty ? "free" : "team")
        }
        if !key.isEmpty {
            try await run(executable, licenseArguments(configFile: configFile, key: key), what: "Setting the license key")
            EventLog.shared.record(phase: "warp", kind: "licenseSet", detail: "WARP+ key bound")
        }
    }

    /// usque logs its reason on failure and exits non-zero (log.Fatalf).
    private static func run(_ executable: URL, _ arguments: [String], what: String) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let p = Process()
            p.executableURL = executable
            p.arguments = arguments
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            p.standardInput = FileHandle.nullDevice   // never hang on a y/n prompt
            p.terminationHandler = { proc in
                let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                guard proc.terminationStatus != 0 else { return continuation.resume() }
                let reason = output.split(whereSeparator: \.isNewline).last.map(String.init)
                    ?? "exit status \(proc.terminationStatus)"
                EventLog.shared.record(phase: "warp", level: .error, kind: "setupFailed", detail: reason)
                continuation.resume(throwing: Failure(
                    message: "\(what) failed: \(reason). Check your internet connection and any key you entered, then try again."))
            }
            do { try p.run() } catch {
                continuation.resume(throwing: Failure(message: "Could not launch usque: \(error.localizedDescription)"))
            }
        }
    }
}
#endif
