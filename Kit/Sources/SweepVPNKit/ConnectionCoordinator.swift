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
        /// How long a relay actually carried the tunnel before it dropped.
        /// Ordering the pool by this is the difference between redialling the
        /// relay that just died at ten seconds and picking the one that held
        /// five minutes.
        public var onRelayLifetime: @Sendable (ServerID, TimeInterval) -> Void

        public init(onAuthenticated: @escaping @Sendable (TunnelAdapter, Server) -> Void,
                    onInbound: @escaping @Sendable ([Data], [NSNumber]) -> Void,
                    onExhausted: @escaping @Sendable (TunnelErrorKind) -> Void,
                    onEvent: @escaping @Sendable (String, String) -> Void = { _, _ in },
                    onRelayLifetime: @escaping @Sendable (ServerID, TimeInterval) -> Void
                        = { _, _ in }) {
            self.onAuthenticated = onAuthenticated
            self.onInbound = onInbound
            self.onExhausted = onExhausted
            self.onEvent = onEvent
            self.onRelayLifetime = onRelayLifetime
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
    /// Relays that have already failed or dropped this session. A rung is only
    /// out of options once every server that can carry it is in here.
    private var burned: Set<ServerID> = []
    /// The relay each racing rung is currently dialling, so a failure can be
    /// charged to the right one.
    private var dialling: [ProtocolRung: Server] = [:]
    /// Which attempt for a rung is current.
    ///
    /// A retired adapter still speaks: `stop()` makes OpenVPN 3 emit
    /// DISCONNECTED and tears the Worker leg down, and both route back here as
    /// a failure — arriving *after* the replacement attempt has been armed.
    /// Acting on that stale report re-entered `retryOrDescend`, so two callers
    /// armed the same rung and two adapters started. `racing` is keyed by rung,
    /// so the second one overwrote the first: the first was never stopped,
    /// never stoppable, and spent the rest of the session dialling relays,
    /// burning them and failing legs under a rung it no longer owned. That is
    /// the duplicate `rungStarted`/`relayTunnelUp` pair, the stray `wssFailed`,
    /// and the throughput collapse that followed it.
    ///
    /// Every callback carries the generation it was armed by and is ignored
    /// unless it is still current, so a retired attempt cannot reach the ladder.
    private var generation: [ProtocolRung: Int] = [:]
    /// Full sweeps of the relay pool since the last success. Bounded so a
    /// network where nothing works still fails closed instead of spinning.
    private var sweeps = 0
    /// Relays recover: the pool is re-tried from the top this many times before
    /// the ladder gives up, which is what lets a long session outlive every
    /// relay in it dying at least once.
    private static let maxSweeps = 5
    /// Single-relay fallback: with no pool to hand over to, a rung that carried
    /// a working tunnel still earns one redial before the ladder moves on.
    private var retriedAfterLoss: Set<ProtocolRung> = []
    private var hadLiveTunnel: Set<ProtocolRung> = []
    private var racing: [ProtocolRung: TunnelAdapter] = [:]
    private var winner: TunnelAdapter?
    private var server: Server?
    /// When the live tunnel started carrying traffic, so its length can be
    /// charged to the relay when it ends.
    private var winnerSince: Date?
    private var raceDeadline: DispatchWorkItem?
    /// Consecutive throughput samples under the floor, so one quiet interval
    /// (the user simply not loading anything) never costs a handover.
    private var slowSamples = 0
    /// When the last throughput-driven handover happened, so a uniformly slow
    /// network cannot turn the pool into a carousel.
    private var lastVoluntarySwitch: Date?

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
    /// Ask the live rung whether it still looks alive, on its own terms.
    /// No live rung is not "unhealthy" — there is simply nothing to sample.
    public func sampleLiveness() -> Bool? { winner?.sampleLiveness() }
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

        // The deadline has to suit the slowest rung actually in flight. Applying
        // WireGuard's 3 s to an OpenVPN attempt killed it long before its TLS
        // negotiation and PUSH_REPLY could complete — which, with a pinned
        // relay, meant the only permitted rung was abandoned every single time
        // and the tunnel could never come up. Every attempt still gets *a*
        // deadline, so a hung rung cannot stall the ladder.
        let timeout = fresh.contains(where: \.handshakeIsSlow)
            ? constants.slowRungDeadline
            : constants.raceDeadline
        let deadline = DispatchWorkItem { [weak self] in self?.raceTimedOut() }
        raceDeadline?.cancel()
        raceDeadline = deadline
        queue.asyncAfter(deadline: .now() + timeout, execute: deadline)
    }

    /// The best relay for this rung that has not already failed this session.
    ///
    /// `catalog.fastest()` alone was the bug behind "connected, then dead": it
    /// returns the same relay every time, so the post-loss retry redialled the
    /// machine that had just dropped us — and VPN Gate answers an immediate
    /// re-auth to the same relay with AUTH_FAILED, which openvpn3 treats as
    /// fatal. Rotating is what turns a relay drop into a handover.
    private func nextServer(for rung: ProtocolRung) -> Server? {
        let usable = catalog.ranked().map(\.0).filter { $0.supports(rung) }
        return usable.first { !burned.contains($0.id) } ?? usable.first
    }

    /// Retire the attempt on this rung: stop the adapter and invalidate its
    /// callbacks. Every path that abandons an adapter goes through here, so
    /// there is exactly one place that can leave one running.
    @discardableResult
    private func discard(_ rung: ProtocolRung) -> TunnelAdapter? {
        generation[rung] = (generation[rung] ?? 0) + 1
        let adapter = racing.removeValue(forKey: rung)
        adapter?.stop()
        return adapter
    }

    private func startAdapter(for rung: ProtocolRung) {
        guard winner == nil else { return }
        // One attempt per rung in flight. Without this, a second caller arming
        // the same rung silently orphans the adapter already running on it.
        guard racing[rung] == nil else { return }
        guard let host = nextServer(for: rung) else {
            callbacks.onEvent("rungSkipped", rung.shortName)
            queue.async { [weak self] in self?.rungFailed(rung) }
            return
        }
        dialling[rung] = host

        let generation = (self.generation[rung] ?? 0) + 1
        self.generation[rung] = generation

        do {
            let adapter = try build(rung, host)
            racing[rung] = adapter
            callbacks.onEvent("rungStarted", rung.shortName)
            adapter.start(
                onAuthenticated: { [weak self] in
                    self?.queue.async {
                        guard let self, self.generation[rung] == generation else { return }
                        self.commit(rung: rung, server: host)
                    }
                },
                onInbound: { [weak self] packets, protocols in
                    guard let self, self.winner?.rung == rung,
                          self.generation[rung] == generation else { return }
                    self.callbacks.onInbound(packets, protocols)
                },
                onFailure: { [weak self] kind in
                    self?.queue.async {
                        guard let self, self.generation[rung] == generation else { return }
                        self.rungFailed(rung, kind: kind)
                    }
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
        for other in racing.keys where other != rung { discard(other) }
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
        // Deliberately *not* clearing the burn ledger here. Authenticating is
        // cheap — a VPN Gate relay that is about to drop the tunnel four
        // seconds later authenticates just as readily as one that will carry it
        // for an hour — so clearing on the win meant every handover reset the
        // count to zero. The field log is unambiguous: `1/14 relays burned`, on
        // every line, forever. Nothing ever accumulated, so the pool kept
        // re-serving relays that had already failed, `maxSweeps` never engaged
        // and the ladder never descended. The ledger is cleared in `rungFailed`
        // instead, and only for a relay that actually held the tunnel.
        // Keep the winner's relay on the ledger, not clear it: this is the
        // entry that lets a later drop be charged to the relay that dropped us
        // rather than leaving it top of the pool to be redialled.
        dialling = [rung: server]
        winnerSince = Date()
        callbacks.onEvent("rungWon", rung.shortName)
        callbacks.onAuthenticated(adapter, server)
    }

    /// How long a relay has to hold the tunnel before its eventual drop counts
    /// as churn rather than as a failure. Comfortably above the few seconds a
    /// dud survives, comfortably below the minutes a working one manages.
    static let healthyRelaySeconds: TimeInterval = 45

    private func rungFailed(_ rung: ProtocolRung, kind: TunnelErrorKind = .allRungsFailed) {
        // Whichever relay this rung was on has just proved it cannot carry the
        // tunnel right now. Charge the failure to it, not to the protocol.
        let dropped = dialling.removeValue(forKey: rung)
        if let dropped { burned.insert(dropped.id) }
        // A relay that was carrying the tunnel has just told us, by dying, how
        // long it was good for. A relay that never got there scores zero, which
        // is the honest number.
        if let dropped, winner?.rung == rung || winner == nil {
            let lasted = winnerSince.map { Date().timeIntervalSince($0) } ?? 0
            if winner?.rung == rung { winnerSince = nil }
            callbacks.onRelayLifetime(dropped.id, lasted)
            // A relay that carried the tunnel for a real span and then dropped
            // is ordinary churn, and the pool deserves a clean slate. One that
            // died within seconds of authenticating proved nothing, and letting
            // it clear the ledger is what kept the pool cycling through known-
            // dead relays instead of exhausting them and recycling honestly.
            if lasted >= Self.healthyRelaySeconds {
                burned = [dropped.id]
                sweeps = 0
            }
        }

        guard winner == nil else {
            // The live tunnel died. Hand over to another relay rather than
            // retiring the rung — on a pinned-relay build it is the only rung
            // there is, so retiring it is retiring the VPN.
            if winner?.rung == rung {
                hadLiveTunnel.insert(rung)
                callbacks.onEvent("activeRungLost", rung.shortName)
                discard(rung)
                winner = nil
                server = nil
                retryOrDescend(rung, kind: kind)
            }
            return
        }
        discard(rung)
        failed.insert(rung)
        callbacks.onEvent("rungFailed", rung.shortName)
        if racing.isEmpty { retryOrDescend(rung, kind: kind) }
    }

    /// Move this rung onto the next relay, or give up on it and walk the ladder.
    ///
    /// Retrying is only ever a *relay* decision. With a single server there is
    /// nothing to hand over to, so this falls straight through to `descend` and
    /// the ladder behaves exactly as it did before pools existed — including
    /// leaving `attempted` intact, which is what the network memory reads to
    /// decide that this network blocks UDP.
    private func retryOrDescend(_ rung: ProtocolRung,
                                kind: TunnelErrorKind = .allRungsFailed) {
        let carriers = catalog.ranked().map(\.0).filter { $0.supports(rung) }
        guard carriers.count > 1 else {
            // No pool. A rung that had a live tunnel gets the single redial it
            // has always had; anything else walks the ladder unchanged.
            // A relay that answered the redial with AUTH_FAILED will answer the
            // next one the same way — VPN Gate refuses an immediate re-auth to
            // the machine that just dropped you. Spending the one redial there
            // costs the ladder a rung for nothing.
            if winner == nil, kind != .authenticationFailed,
               retriedAfterLoss.insert(rung).inserted, hadLiveTunnel.contains(rung) {
                return retry(rung)
            }
            return descend(now: Date())
        }

        if carriers.contains(where: { !burned.contains($0.id) }) {
            callbacks.onEvent("relayHandover",
                              "\(rung.shortName): \(burned.count)/\(carriers.count) relays burned")
            return retry(rung)
        }
        // Every relay in the pool has failed for this rung. Another sweep is
        // worth trying — relays come back, and a whole pool failing at once is
        // far more often the path than the relays — but not forever.
        sweeps += 1
        guard sweeps < Self.maxSweeps else { return descend(now: Date()) }
        callbacks.onEvent("relayPoolRecycled", "sweep \(sweeps) of \(Self.maxSweeps)")
        burned.removeAll()
        retry(rung)
    }

    /// Re-arm a rung for another relay. `attempt` skips anything already tried,
    /// so the bookkeeping has to be undone here and nowhere else.
    private func retry(_ rung: ProtocolRung) {
        attempted.remove(rung)
        failed.remove(rung)
        attempt([rung], now: Date())
    }

    private func raceTimedOut() {
        guard winner == nil else { return }
        callbacks.onEvent("raceTimedOut", "")
        let stalled = Array(racing.keys)
        for rung in stalled {
            discard(rung)
            if let host = dialling.removeValue(forKey: rung) { burned.insert(host.id) }
        }
        // A relay that never finished its handshake is a burned relay, not a
        // burned protocol — the next one down the pool deserves the same rung.
        for rung in stalled { failed.insert(rung) }
        if let rung = stalled.first { retryOrDescend(rung) } else { descend(now: Date()) }
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
        for rung in racing.keys { discard(rung) }
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

    /// Below this, a relay is not carrying a usable connection. 2 Mbps: enough
    /// that ordinary browsing on a healthy relay never trips it, low enough
    /// that the relays the user experiences as "the VPN is slow" do.
    static let slowRelayBytesPerSecond: Double = 250_000
    /// Two consecutive samples, so a genuinely idle interval is not mistaken
    /// for a slow relay.
    static let slowSamplesBeforeSwitch = 2
    /// A relay gets a fair run before its throughput is held against it.
    static let voluntarySwitchDwell: TimeInterval = 60
    /// And the pool is not re-cut more often than this.
    static let voluntarySwitchCooldown: TimeInterval = 180

    /// Feed the live tunnel's measured throughput.
    ///
    /// A relay that is authenticated and delivering a trickle is invisible to
    /// every check we have: bytes *are* moving, so `sampleLiveness` calls it
    /// healthy and nothing ever hands over. That is exactly the state the user
    /// experiences as "connected but slow". With a pool, the answer is to stop
    /// using this relay and go pick another one.
    public func noteThroughput(bytesPerSecond: Double, now: Date = Date()) {
        queue.async { [weak self] in
            self?.considerFasterRelay(bytesPerSecond, now: now)
        }
    }

    private func considerFasterRelay(_ bytesPerSecond: Double, now: Date) {
        guard let rung = winner?.rung, let active = server, let since = winnerSince else {
            slowSamples = 0
            return
        }
        guard bytesPerSecond < Self.slowRelayBytesPerSecond else {
            slowSamples = 0
            return
        }
        slowSamples += 1
        guard slowSamples >= Self.slowSamplesBeforeSwitch else { return }
        guard now.timeIntervalSince(since) >= Self.voluntarySwitchDwell else { return }
        if let last = lastVoluntarySwitch,
           now.timeIntervalSince(last) < Self.voluntarySwitchCooldown { return }
        // Only worth doing if there is somewhere better to go. With a single
        // relay this is just churn, and the ladder already handles a rung that
        // cannot carry traffic at all.
        let carriers = catalog.ranked().map(\.0).filter { $0.supports(rung) }
        guard carriers.contains(where: { $0.id != active.id && !burned.contains($0.id) })
        else { return }

        slowSamples = 0
        lastVoluntarySwitch = now
        callbacks.onEvent("relayTooSlow",
                          "\(Int(bytesPerSecond / 1024)) KB/s, handing over")
        // Hand over through the same path a drop takes: burn it so the pool
        // moves past it, record what it actually managed, and re-arm the rung.
        // Deliberately not routed through `rungFailed` — a relay that held the
        // tunnel this long would clear the burn ledger there, and the whole
        // point here is that we do not want to come back to it.
        burned.insert(active.id)
        callbacks.onRelayLifetime(active.id, now.timeIntervalSince(since))
        hadLiveTunnel.insert(rung)
        // `discard` before `retry`: stopping the adapter is what makes OpenVPN
        // 3 report DISCONNECTED, and that report used to arrive as a second
        // failure for this rung and arm a second attempt alongside this one.
        discard(rung)
        winner = nil
        server = nil
        winnerSince = nil
        dialling.removeValue(forKey: rung)
        retry(rung)
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
                    // Retire every attempt that is not the one taking over,
                    // rather than dropping them out of `racing` still running.
                    for other in self.racing.keys where other != rung { self.discard(other) }
                    if let old = previous?.rung, old != rung { self.discard(old) }
                    previous?.stop()
                    self.winner = candidate
                    self.server = host
                    self.dialling = [rung: host]
                    // Without this the relay carrying the tunnel after a ladder
                    // switch has no start time, and every throughput check
                    // silently bails instead of ever handing over.
                    self.winnerSince = Date()
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
