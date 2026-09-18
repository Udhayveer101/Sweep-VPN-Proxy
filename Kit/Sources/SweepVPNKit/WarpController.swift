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
    private var failureTimes: [Date] = []
    private var lastRestart: Date = .distantPast
    private var restarting = false
    private var stopped = false
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
        let plain = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
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
    func ingest(log text: String) {
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            switch Self.classify(line) {
            case .listening:
                stallTimer?.cancel()
                stallTimer = nil
                state = .running
                record(.info, "listening", line)
            case .connected:
                record(.info, "connected", line)
            // A loss line only counted when it named a failure, as before .lost existed.
            case .error, .lost where line.lowercased().contains("failed") || line.lowercased().contains("error"):
                record(.warn, "log", line)
                if noteFailure(line) { restartWedgedTunnel(line) }
            case .lost, nil:
                break
            }
        }
    }

    /// usque only tears the session down when a write fails with a connect-ip
    /// CloseError (api/tunnel.go). A MASQUE session whose HTTP/2 pipe has been
    /// closed underneath it fails with `io: read/write on closed pipe` instead,
    /// which it logs as "continuing..." forever while the read pump stays parked
    /// — so it reports Connected while nothing flows and never reconnects. Seen
    /// 2026-09-13: a minute of traffic, then every lookup timing out for good.
    /// We supervise the process, so we are the ones who can end that: a write
    /// failure is acted on at once, and a burst of dial failures counts as the
    /// same wedge in case the write pump stays quiet.
    static let wedgeWindow: TimeInterval = 10
    static let wedgeBurst = 4
    static let restartFloor: TimeInterval = 20

    /// `true` when this error line means the tunnel is wedged and the child
    /// should be relaunched. Bookkeeping only — the process work is separate so
    /// this stays testable. `now` is injectable for the same reason.
    func noteFailure(_ line: String, now: Date = Date()) -> Bool {
        let writeFailed = line.contains("closed pipe")
            || line.contains("Error writing to IP connection")
        lock.lock()
        defer { lock.unlock() }
        failureTimes.append(now)
        failureTimes.removeAll { now.timeIntervalSince($0) > Self.wedgeWindow }
        let wedged = writeFailed || failureTimes.count >= Self.wedgeBurst
        guard wedged, !restarting, process != nil,
              now.timeIntervalSince(lastRestart) >= Self.restartFloor else { return false }
        lastRestart = now
        failureTimes.removeAll()
        restarting = true
        return true
    }

    /// Tests need a controller that believes a child is running without one —
    /// the state a real relaunch lands in.
    func pretendRunningForTests() {
        lock.lock(); defer { lock.unlock() }
        process = Process()
        restarting = false
    }

    private func restartWedgedTunnel(_ line: String) {
        record(.warn, "restarting", "tunnel wedged: \(line)")
        DispatchQueue.global().async { [self] in
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
    enum LogEvent: Equatable { case listening, connected, lost, error }

    /// Lines from usque 2026-09 (see WarpControllerTests for real samples).
    /// Shared by the macOS child-process supervisor and the iOS extension.
    static func classify(_ line: String) -> LogEvent? {
        if line.contains("SOCKS proxy listening on") { return .listening }
        if line.contains("Connected to MASQUE server") { return .connected }
        if line.contains("Tunnel connection lost") { return .lost }
        let l = line.lowercased()
        if l.contains("failed") || l.contains("error") { return .error }
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
