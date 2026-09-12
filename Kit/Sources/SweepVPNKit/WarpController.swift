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
    var arguments: [String] {
        ["-c", configFile.path, "socks",
         "-s", sni, "--http2",
         "--always-reconnect", "--dns-timeout", "5s",
         "-d", "1.1.1.1", "-d", "1.0.0.1",
         "-b", "127.0.0.1", "-p", String(socksPort)]
    }

    public func start(onState: @escaping @Sendable (State) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        self.onState = onState
        guard process == nil else { return }

        let dir = configFile.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        guard FileManager.default.fileExists(atPath: configFile.path) else {
            state = .failed("No WARP registration. Run `usque -c \"\(configFile.path)\" register -a` once, then turn WARP on again.")
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
            case .error:
                record(.warn, "log", line)
            case nil:
                break
            }
        }
    }

    enum LogEvent: Equatable { case listening, connected, error }

    static func classify(_ line: String) -> LogEvent? {
        if line.contains("SOCKS proxy listening on") { return .listening }
        if line.contains("Connected to MASQUE server") { return .connected }
        let l = line.lowercased()
        if l.contains("failed") || l.contains("error") { return .error }
        return nil
    }

    private func record(_ level: LogEntry.Level, _ kind: String, _ detail: String) {
        EventLog.shared.record(phase: "warp", level: level, kind: kind, detail: detail)
    }
}
#endif
