import Foundation
import SweepVPNCore

/// Drives the ladder at runtime: races a diverse set of rungs on an unknown
/// network, commits to the first one that *authenticates* (not the first that
/// merely connects), walks down on failure, and records what worked so the next
/// connect on this network is instant.
///
/// It is deliberately free of NetworkExtension types so the whole fallback
/// behaviour can be tested on the host with fake adapters.
public final class ConnectionCoordinator: @unchecked Sendable {
    public typealias AdapterBuilder = @Sendable (ProtocolRung, Server) throws -> TunnelAdapter

    public struct Callbacks: Sendable {
        public var onAuthenticated: @Sendable (TunnelAdapter, Server) -> Void
        public var onInbound: @Sendable ([Data], [NSNumber]) -> Void
        public var onExhausted: @Sendable (TunnelErrorKind) -> Void
        public var onEvent: @Sendable (String, String) -> Void

        public init(onAuthenticated: @escaping @Sendable (TunnelAdapter, Server) -> Void,
                    onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                    onExhausted: @escaping @Sendable (TunnelErrorKind) -> Void,
                    onEvent: @escaping @Sendable (String, String) -> Void = { _, _ in }) {
            self.onAuthenticated = onAuthenticated
            self.onInbound = onInbound
            self.onExhausted = onExhausted
            self.onEvent = onEvent
        }
    }

    private let build: AdapterBuilder
    private let callbacks: Callbacks
    private let constants: AutoModeConstants
    private let queue: DispatchQueue

    private var engine: AutoModeEngine
    private var catalog: ServerCatalog
    private var memory: NetworkMemory
    private var attempted: Set<ProtocolRung> = []
    private var failed: Set<ProtocolRung> = []
    private var racing: [ProtocolRung: TunnelAdapter] = [:]
    private var winner: TunnelAdapter?
    private var server: Server?
    private var raceDeadline: DispatchWorkItem?

    /// What the coordinator learned about this network, for the caller to persist.
    public private(set) var updatedMemory: NetworkMemory

    public init(engine: AutoModeEngine, catalog: ServerCatalog, memory: NetworkMemory,
                constants: AutoModeConstants = .init(),
                queue: DispatchQueue = DispatchQueue(label: "vpn.sweep.coordinator"),
                build: @escaping AdapterBuilder, callbacks: Callbacks) {
        self.engine = engine
        self.catalog = catalog
        self.memory = memory
        self.updatedMemory = memory
        self.constants = constants
        self.queue = queue
        self.build = build
        self.callbacks = callbacks
    }

    public var activeRung: ProtocolRung? { winner?.rung }
    public var activeServer: Server? { server }
    /// Seconds since the live rung last completed a handshake, or -1.
    public var handshakeAgeSeconds: Int64 { winner?.lastHandshakeAgeSeconds ?? -1 }
    public var transferred: (tx: UInt64, rx: UInt64) { winner?.transferred ?? (0, 0) }

    // MARK: - Starting

    public func start(signals: NetworkSignals, now: Date = Date()) {
        let decision = engine.decideStart(memory: memory, signals: signals, now: now)
        switch decision {
        case .connect(let rung):
            attempt([rung], now: now)
        case .race(let rungs):
            attempt(rungs, now: now)
        case .failClosed(let kind):
            callbacks.onExhausted(kind)
        default:
            attempt([.wireGuardUDP], now: now)
        }
    }

    /// Happy-Eyeballs-style: stagger the starts, keep them all alive until one
    /// authenticates, then stop the losers. The tunnel is never opened for a
    /// rung that merely completed a TCP connect.
    private func attempt(_ rungs: [ProtocolRung], now: Date) {
        guard winner == nil else { return }
        let fresh = rungs.filter { !attempted.contains($0) }
        guard !fresh.isEmpty else { return descend(now: now) }

        for (index, rung) in fresh.enumerated() {
            attempted.insert(rung)
            queue.asyncAfter(deadline: .now() + constants.raceStagger * Double(index)) { [weak self] in
                self?.startAdapter(for: rung)
            }
        }

        let deadline = DispatchWorkItem { [weak self] in self?.raceTimedOut() }
        raceDeadline?.cancel()
        raceDeadline = deadline
        queue.asyncAfter(deadline: .now() + constants.raceDeadline, execute: deadline)
    }

    private func startAdapter(for rung: ProtocolRung) {
        guard winner == nil else { return }
        guard let server = catalog.fastest() ?? catalog.servers.first(where: { $0.supports(rung) }),
              server.supports(rung) || catalog.servers.contains(where: { $0.supports(rung) }) else {
            callbacks.onEvent("rungSkipped", rung.shortName)
            return
        }
        let host = server.supports(rung)
            ? server
            : (catalog.servers.first { $0.supports(rung) } ?? server)

        do {
            let adapter = try build(rung, host)
            racing[rung] = adapter
            callbacks.onEvent("rungStarted", rung.shortName)
            adapter.start(
                onAuthenticated: { [weak self] in
                    self?.queue.async { self?.commit(rung: rung, server: host) }
                },
                onInbound: { [weak self] packets, protocols in
                    guard let self, self.winner?.rung == rung else { return }
                    self.callbacks.onInbound(packets, protocols)
                },
                onFailure: { [weak self] _ in
                    self?.queue.async { self?.rungFailed(rung) }
                })
        } catch {
            callbacks.onEvent("rungUnavailable", rung.shortName)
            queue.async { [weak self] in self?.rungFailed(rung) }
        }
    }

    // MARK: - Outcomes

    private func commit(rung: ProtocolRung, server: Server) {
        guard winner == nil, let adapter = racing[rung] else { return }
        raceDeadline?.cancel(); raceDeadline = nil
        winner = adapter
        self.server = server
        for (other, loser) in racing where other != rung { loser.stop() }
        racing = [rung: adapter]
        let now = Date()
        engine.noteConnected(rung: rung, now: now)
        updatedMemory.noteSuccess(rung: rung, now: now)
        // Learn from what had to fail before this rung won: a network that killed
        // every UDP rung is remembered as UDP-blocked, and one that only allowed
        // a web-shaped rung is remembered as filtering.
        if !rung.isUDP, failed.contains(where: \.isUDP) { updatedMemory.noteUDPBlocked(now: now) }
        if rung.looksLikeWeb, failed.contains(where: { !$0.looksLikeWeb }) {
            updatedMemory.noteHostile(now: now)
        }
        callbacks.onEvent("rungWon", rung.shortName)
        callbacks.onAuthenticated(adapter, server)
    }

    private func rungFailed(_ rung: ProtocolRung) {
        guard winner == nil else {
            // The live tunnel died: treat it as a reconnect on the next rung.
            if winner?.rung == rung {
                callbacks.onEvent("activeRungLost", rung.shortName)
                winner?.stop()
                winner = nil
                racing.removeValue(forKey: rung)
                descend(now: Date())
            }
            return
        }
        racing.removeValue(forKey: rung)?.stop()
        failed.insert(rung)
        callbacks.onEvent("rungFailed", rung.shortName)
        if racing.isEmpty { descend(now: Date()) }
    }

    private func raceTimedOut() {
        guard winner == nil else { return }
        callbacks.onEvent("raceTimedOut", "")
        for (rung, adapter) in racing {
            adapter.stop()
            failed.insert(rung)
        }
        racing.removeAll()
        descend(now: Date())
    }

    /// Try the next untried rung. When the UDP rungs are the ones that died,
    /// remember that: this network blocks UDP, and possibly filters actively.
    private func descend(now: Date) {
        let permitted = engine.preference.permittedRungs(enabledTiers: engine.enabledRungs)
        if attempted.contains(where: \.isUDP), winner == nil {
            updatedMemory.noteUDPBlocked(now: now)
        }
        guard let next = permitted.first(where: { !attempted.contains($0) }) else {
            if attempted.contains(where: \.looksLikeWeb) { updatedMemory.noteHostile(now: now) }
            callbacks.onExhausted(.allRungsFailed)
            return
        }
        if next.looksLikeWeb { updatedMemory.noteHostile(now: now) }
        attempt([next], now: now)
    }

    // MARK: - Running tunnel

    public func send(packets: [Data], protocols: [NSNumber]) {
        winner?.send(packets: packets, protocols: protocols)
    }

    public func reassert() {
        winner?.reassert()
    }

    public func stop() {
        raceDeadline?.cancel(); raceDeadline = nil
        for (_, adapter) in racing { adapter.stop() }
        racing.removeAll()
        winner = nil
    }

    /// Feed measured health; may walk the ladder down (or back up) per the
    /// hysteresis rules.
    public func observe(health: LinkHealth, now: Date = Date()) {
        let decision = engine.observe(health: health, now: now)
        switch decision {
        case .downgrade(let rung, let reason):
            guard rung != winner?.rung else { return }
            callbacks.onEvent("ladderDown", "\(reason.rawValue)->\(rung.shortName)")
            switchTo(rung, now: now)
        case .upgrade(let rung):
            callbacks.onEvent("ladderUp", rung.shortName)
            switchTo(rung, now: now)
        default:
            break
        }
    }

    /// A rung change keeps the old adapter alive until the new one authenticates,
    /// so the tunnel never drops to "open" in between — and if the new rung
    /// fails, the old one is still there.
    private func switchTo(_ rung: ProtocolRung, now: Date) {
        guard let server = catalog.fastest() ?? catalog.servers.first else { return }
        let host = server.supports(rung) ? server : (catalog.servers.first { $0.supports(rung) } ?? server)
        guard let candidate = try? build(rung, host) else {
            engine.noteFailedSwitch(now: now)
            return
        }
        let previous = winner
        candidate.start(
            onAuthenticated: { [weak self] in
                guard let self else { return }
                self.queue.async {
                    previous?.stop()
                    self.winner = candidate
                    self.server = host
                    self.racing = [rung: candidate]
                    self.engine.noteConnected(rung: rung, now: Date())
                    self.engine.noteSuccessfulSwitch()
                    self.updatedMemory.noteSuccess(rung: rung, now: Date())
                    self.callbacks.onAuthenticated(candidate, host)
                }
            },
            onInbound: { [weak self] packets, protocols in
                guard let self, self.winner === candidate else { return }
                self.callbacks.onInbound(packets, protocols)
            },
            onFailure: { [weak self] _ in
                guard let self else { return }
                self.queue.async {
                    candidate.stop()
                    self.engine.noteFailedSwitch(now: Date())
                    self.callbacks.onEvent("switchFailed", rung.shortName)
                }
            })
    }
}
