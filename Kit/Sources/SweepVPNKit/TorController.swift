#if os(macOS)
import Foundation

/// Runs Tor as a child process of the *app*, never of the network extension.
///
/// The extension is jetsam-capped (vault 01-Apple-Platform/Network-Extension-Process-Memory-Limit:
/// ~50 MiB on iOS, with kills observed well below that under system pressure).
/// Tor plus OpenSSL and libevent would compete with the packet buffers for that
/// budget, so it lives in the app and is reached over a loopback SOCKS port.
/// Because the tunnel carries the app's own traffic, Tor's circuits are built
/// *through* the VPN — which is the ordering "Tor over VPN" actually means.
public final class TorController: @unchecked Sendable {

    public enum State: Equatable, Sendable {
        case stopped
        case starting(percent: Int, summary: String)
        case running                 // bootstrapped to 100%
        case failed(String)
    }

    /// Where other components should point their SOCKS clients.
    public let socksPort: Int
    private let dataDirectory: URL
    private let executable: URL

    private var process: Process?
    private let lock = NSLock()
    private var onState: (@Sendable (State) -> Void)?
    private(set) public var state: State = .stopped {
        didSet { if state != oldValue { onState?(state) } }
    }

    /// How Tor should reach the network.
    public enum Reachability: Equatable, Sendable {
        /// Connect straight to relays. Fine over the VPN, or on an unfiltered network.
        case direct
        /// Connect through obfs4 bridges. Needed where Tor itself is blocked —
        /// which is the observed behaviour on Indian consumer ISPs, where a direct
        /// bootstrap stalls at 14% with CONNECTRESET.
        case bridges([String])

        /// Tor Project's published default obfs4 bridges, the same set Tor Browser
        /// ships. They are public by design, but they are also widely blocked, so
        /// they are a fallback and not a substitute for bridges requested from
        /// https://bridges.torproject.org for a specific network.
        public static var defaultBridges: Reachability {
            .bridges([
                "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
                "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
                "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
                "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0",
            ])
        }
    }

    /// `nil` when the app was built without the bundled tor (see Tools/bundle-tor.sh).
    public static func bundledExecutable(bundle: Bundle = .main) -> URL? {
        let url = bundle.bundleURL.appendingPathComponent("Contents/Resources/tor/tor")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// Path to the bundled obfs4 pluggable transport, if present.
    public static func bundledObfs4(bundle: Bundle = .main) -> URL? {
        let url = bundle.bundleURL.appendingPathComponent("Contents/Resources/tor/obfs4proxy")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    private let obfs4: URL?
    private var reachability: Reachability = .direct
    /// Set once we have already retried with bridges, so we do not loop.
    private var triedBridges = false
    private var stallTimer: DispatchSourceTimer?

    public init?(socksPort: Int = 9150, bundle: Bundle = .main) {
        guard let exe = Self.bundledExecutable(bundle: bundle) else { return nil }
        self.executable = exe
        self.obfs4 = Self.bundledObfs4(bundle: bundle)
        self.socksPort = socksPort
        // Application Support inside the sandbox container: writable, and it
        // persists the consensus so restarts do not re-download the directory.
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask).first!
        self.dataDirectory = base.appendingPathComponent("SweepVPN/tor", isDirectory: true)
    }

    public func start(reachability: Reachability = .direct,
                      onState: @escaping @Sendable (State) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        self.onState = onState
        self.reachability = reachability
        guard process == nil else { return }

        do {
            try FileManager.default.createDirectory(at: dataDirectory,
                                                    withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            state = .failed("Could not create Tor's data directory: \(error.localizedDescription)")
            return
        }

        let p = Process()
        p.executableURL = executable
        p.arguments = [
            "--SocksPort", "127.0.0.1:\(socksPort)",
            "--DataDirectory", dataDirectory.path,
            // Bind nothing else. No control port: we read bootstrap progress off
            // stdout instead, which avoids exposing an authenticated control
            // socket that any local process could try to reach.
            "--ControlPort", "0",
            "--SocksPolicy", "accept 127.0.0.1/32",
            "--SocksPolicy", "reject *",
            "--AvoidDiskWrites", "1",
            "--ClientOnly", "1",
            // Never act as a relay or exit for anyone else.
            "--ORPort", "0",
            "--ExitRelay", "0",
            "--Log", "notice stdout",
        ]

        if case .bridges(let lines) = reachability, let obfs4, !lines.isEmpty {
            p.arguments?.append(contentsOf: [
                "--UseBridges", "1",
                "--ClientTransportPlugin", "obfs4 exec \(obfs4.path)",
            ])
            for line in lines {
                p.arguments?.append(contentsOf: ["--Bridge", line])
            }
        }

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
            self.lock.lock(); self.process = nil; self.lock.unlock()
            if case .running = self.state {
                self.state = .failed("Tor exited unexpectedly (status \(proc.terminationStatus)).")
            } else if case .failed = self.state {
                // keep the specific reason already parsed from the log
            } else {
                self.state = .stopped
            }
        }

        do {
            try p.run()
            process = p
            state = .starting(percent: 0, summary: bridgeSummary())
            armStallWatchdog()
        } catch {
            state = .failed("Could not launch Tor: \(error.localizedDescription)")
        }
    }

    public func stop() {
        lock.lock()
        let p = process
        process = nil
        stallTimer?.cancel()
        stallTimer = nil
        triedBridges = false
        lock.unlock()
        p?.terminate()
        state = .stopped
    }

    private func bridgeSummary() -> String {
        if case .bridges = reachability { return "Starting Tor via bridges" }
        return "Starting Tor"
    }

    /// A blocked network does not fail — it stalls. Tor keeps retrying relays it
    /// can never reach, so without a deadline the UI sits at 14% forever. If a
    /// direct bootstrap has not completed in time, retry once over bridges.
    private func armStallWatchdog(seconds: Int = 45) {
        stallTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .seconds(seconds))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard self.state != .running else { return }
            self.lock.lock()
            let shouldFallBack = !self.triedBridges && self.obfs4 != nil
            self.triedBridges = true
            self.lock.unlock()

            guard shouldFallBack, let onState = self.onState else {
                if self.state != .running {
                    self.state = .failed("""
                    Tor could not connect. This network appears to block it. \
                    Connect the VPN first and try again, or request bridges from \
                    https://bridges.torproject.org
                    """)
                }
                return
            }
            self.stop()
            self.start(reachability: .defaultBridges, onState: onState)
        }
        timer.resume()
        stallTimer = timer
    }

    /// Parses tor's `notice`-level bootstrap lines. Format is stable across
    /// releases: `... [notice] Bootstrapped 45% (requesting_descriptors): Asking ...`
    func ingest(log text: String) {
        for line in text.split(separator: "\n") {
            guard let progress = Self.parseBootstrap(String(line)) else { continue }
            if progress.percent >= 100 {
                stallTimer?.cancel()
                stallTimer = nil
                state = .running
            } else {
                state = .starting(percent: progress.percent, summary: progress.summary)
            }
        }
    }

    struct Bootstrap: Equatable { let percent: Int; let summary: String }

    static func parseBootstrap(_ line: String) -> Bootstrap? {
        guard let range = line.range(of: "Bootstrapped ") else { return nil }
        let rest = line[range.upperBound...]
        guard let pctEnd = rest.firstIndex(of: "%"),
              let percent = Int(rest[rest.startIndex..<pctEnd]) else { return nil }
        // Prefer the human summary after the colon; fall back to the tag.
        let after = rest[rest.index(after: pctEnd)...]
        let summary: String
        if let colon = after.firstIndex(of: ":") {
            summary = after[after.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        } else {
            summary = after.trimmingCharacters(in: CharacterSet(charactersIn: " ()"))
        }
        return Bootstrap(percent: percent, summary: summary.isEmpty ? "Connecting" : summary)
    }
}
#endif
