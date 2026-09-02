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
        /// Connect straight to relays. This is the path that works once the VPN
        /// is up, because the ISP then sees only WireGuard to the exit server.
        case direct
        /// obfs4 bridges: relays disguised as random bytes.
        case bridges([String])
        /// Snowflake: rendezvous with volunteer proxies over a domain-fronted
        /// broker, then WebRTC. Beats IP blocking of bridges.
        case snowflake
        /// meek: every byte tunnelled inside HTTPS to a big CDN. Slowest, but
        /// the hardest to block without blocking the CDN itself.
        case meek

        /// Tor Project's published default obfs4 bridges, the same set Tor
        /// Browser ships. Public by design and therefore widely blocked, so they
        /// are a step in the chain, not a substitute for bridges requested from
        /// https://bridges.torproject.org for a specific network.
        static let defaultBridgeLines = [
            "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
            "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
            "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
            "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0",
        ]

        public static var defaultBridges: Reachability { .bridges(defaultBridgeLines) }

        /// Ordered from fastest to most evasive. Each step costs a stall timeout,
        /// so the cheap options come first. Measured on an Indian consumer ISP:
        /// direct stalls at 14% (CONNECTRESET), the public obfs4 bridges are
        /// blocked, snowflake reaches its broker but its WebRTC data channel
        /// times out, and meek reaches a relay but does not finish either. On
        /// that network only Tor-over-VPN completes — which is why the app tells
        /// the user to connect the VPN rather than pretending a transport will
        /// save them.
        static func chain(userBridges: [String]) -> [Reachability] {
            var steps: [Reachability] = [.direct]
            if !userBridges.isEmpty { steps.append(.bridges(userBridges)) }
            steps.append(.bridges(defaultBridgeLines))
            steps.append(.snowflake)
            steps.append(.meek)
            return steps
        }

        var label: String {
            switch self {
            case .direct:    return "Starting Tor"
            case .bridges:   return "Trying Tor bridges"
            case .snowflake: return "Trying Snowflake"
            case .meek:      return "Trying meek (slow)"
            }
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

    /// Any bundled pluggable-transport binary, by filename.
    private static func bundledTransport(_ name: String, bundle: Bundle = .main) -> URL? {
        let url = bundle.bundleURL.appendingPathComponent("Contents/Resources/tor/\(name)")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    private let obfs4: URL?
    private let snowflake: URL?
    private let meek: URL?
    private var reachability: Reachability = .direct
    /// Remaining steps of the transport chain, consumed on each stall.
    private var remainingSteps: [Reachability] = []
    /// True while we are tearing down one transport to start the next.
    private var advancing = false
    private var stallTimer: DispatchSourceTimer?

    public init?(socksPort: Int = 9150, bundle: Bundle = .main) {
        guard let exe = Self.bundledExecutable(bundle: bundle) else { return nil }
        self.executable = exe
        self.obfs4 = Self.bundledObfs4(bundle: bundle)
        self.snowflake = Self.bundledTransport("snowflake-client", bundle: bundle)
        self.meek = Self.bundledTransport("meek-client", bundle: bundle)
        self.socksPort = socksPort
        // Application Support inside the sandbox container: writable, and it
        // persists the consensus so restarts do not re-download the directory.
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask).first!
        self.dataDirectory = base.appendingPathComponent("SweepVPN/tor", isDirectory: true)
    }

    /// Walks the whole transport chain, most-preferred first.
    public func start(userBridges: [String] = [],
                      onState: @escaping @Sendable (State) -> Void) {
        var steps = Reachability.chain(userBridges: userBridges)
        let first = steps.removeFirst()
        lock.lock()
        remainingSteps = steps
        lock.unlock()
        start(reachability: first, onState: onState)
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

        p.arguments?.append(contentsOf: bridgeArguments(for: reachability))

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
            self.process = nil
            // We killed this one on purpose to try the next transport; the
            // successor has already published its own state, so reporting
            // "stopped" here would clobber it.
            let deliberate = self.advancing
            self.advancing = false
            self.lock.unlock()
            if deliberate { return }
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
            state = .starting(percent: 0, summary: reachability.label)
            armStallWatchdog()
        } catch {
            state = .failed("Could not launch Tor: \(error.localizedDescription)")
        }
    }

    /// Kill the current tor without discarding the remaining chain, so the next
    /// transport can be tried. `stop()` is the user-facing teardown and clears it.
    private func stopProcessOnly() {
        lock.lock()
        let p = process
        process = nil
        advancing = (p != nil)
        stallTimer?.cancel()
        stallTimer = nil
        lock.unlock()
        p?.terminate()
    }

    public func stop() {
        lock.lock()
        let p = process
        process = nil
        stallTimer?.cancel()
        stallTimer = nil
        remainingSteps = []
        lock.unlock()
        p?.terminate()
        state = .stopped
    }

    /// Tor is configured entirely on the command line: a transport plugin plus
    /// the bridge lines that name it. A transport whose binary is missing
    /// contributes nothing rather than producing a half-configured tor that
    /// would fail in a confusing way.
    private func bridgeArguments(for reachability: Reachability) -> [String] {
        switch reachability {
        case .direct:
            return []

        case .bridges(let lines):
            guard let obfs4, !lines.isEmpty else { return [] }
            var args = ["--UseBridges", "1",
                        "--ClientTransportPlugin", "obfs4 exec \(obfs4.path)"]
            for line in lines { args += ["--Bridge", line] }
            return args

        case .snowflake:
            guard let snowflake else { return [] }
            // The address is a placeholder by design: snowflake rendezvouses
            // through the broker named in `url`, fronted behind `fronts`, and
            // never dials this IP.
            let bridge = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
                + "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
                + "url=https://1098762253.rsc.cdn77.org/ "
                + "fronts=www.cdn77.com,www.phpmyadmin.net "
                + "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 "
                + "utls-imitate=hellorandomizedalpn"
            return ["--UseBridges", "1",
                    "--ClientTransportPlugin", "snowflake exec \(snowflake.path)",
                    "--Bridge", bridge]

        case .meek:
            guard let meek else { return [] }
            let bridge = "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE "
                + "url=https://1314488750.rsc.cdn77.org/ front=www.phpmyadmin.net "
                + "utls=HelloRandomizedALPN"
            return ["--UseBridges", "1",
                    "--ClientTransportPlugin", "meek_lite exec \(meek.path)",
                    "--Bridge", bridge]
        }
    }

    /// A blocked network does not fail — it stalls. Tor keeps retrying relays it
    /// can never reach, so without a deadline the UI sits at a low percentage
    /// forever. On each stall, move to the next transport in the chain.
    ///
    /// meek gets longer: it tunnels through a CDN and is genuinely slow rather
    /// than stuck, so the deadline that catches a block would also kill a
    /// connection that was going to succeed.
    private func armStallWatchdog(seconds: Int? = nil) {
        stallTimer?.cancel()
        let deadline = seconds ?? (reachability == .meek ? 120 : 45)
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .seconds(deadline))
        timer.setEventHandler { [weak self] in
            guard let self, self.state != .running else { return }

            self.lock.lock()
            let next = self.remainingSteps.isEmpty ? nil : self.remainingSteps.removeFirst()
            let onState = self.onState
            self.lock.unlock()

            guard let next, let onState else {
                self.state = .failed("""
                Tor could not connect on this network — every transport was \
                blocked, including bridges, Snowflake and meek. Connect the VPN \
                first: Tor then builds its circuits from the VPN exit, where it \
                is not blocked. You can also add bridges from \
                https://bridges.torproject.org.
                """)
                return
            }
            self.stopProcessOnly()
            self.start(reachability: next, onState: onState)
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
