import Foundation
import Network
import SweepVPNCore

/// Measures how fast each server actually is from *this* network, so the list
/// can be ordered fastest-first and "Automatic" can pick the real winner rather
/// than a guess from a geo database.
///
/// The probe is a connect-time measurement to the server's own endpoint — no
/// third-party latency service, nothing leaves the device except a packet to a
/// server the user already trusts with their traffic.
public final class ServerProber: @unchecked Sendable {
    public struct Result: Sendable {
        public let id: ServerID
        public let probe: ServerProbe
    }

    private let queue = DispatchQueue(label: "vpn.sweep.prober")
    private let timeout: TimeInterval
    private let samples: Int

    public init(timeout: TimeInterval = 2.0, samples: Int = 3) {
        self.timeout = timeout
        self.samples = max(1, samples)
    }

    /// Probe several servers concurrently; completion carries whatever finished.
    public func probe(_ servers: [Server], rung: ProtocolRung,
                      completion: @escaping @Sendable ([Result]) -> Void) {
        probe(servers, rungs: [rung], completion: completion)
    }

    /// Probe each server on whichever of `rungs` it actually offers. A mixed
    /// list — our own WireGuard peers next to OpenVPN relays — has no single
    /// rung to measure on, and measuring a relay on a port it does not listen
    /// on would score it as dead rather than slow.
    public func probe(_ servers: [Server], rungs: Set<ProtocolRung>,
                      completion: @escaping @Sendable ([Result]) -> Void) {
        let group = DispatchGroup()
        let collector = Collector()
        for server in servers {
            let preferred = server.bestRung(in: rungs)
            guard let endpoint = server.endpoints.first(where: { $0.rung == preferred })
                    ?? server.endpoints.first else { continue }
            group.enter()
            measure(endpoint: endpoint) { probe in
                if let probe { collector.add(.init(id: server.id, probe: probe)) }
                group.leave()
            }
        }
        group.notify(queue: queue) { completion(collector.all()) }
    }

    /// Round-trip time to the endpoint, taken `samples` times; loss is the
    /// fraction of attempts that never answered.
    public func measure(endpoint: ServerEndpoint,
                        completion: @escaping @Sendable (ServerProbe?) -> Void) {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else { return completion(nil) }
        let host = NWEndpoint.Host(endpoint.host)
        let collector = SampleCollector()
        let group = DispatchGroup()

        for index in 0..<samples {
            group.enter()
            queue.asyncAfter(deadline: .now() + 0.05 * Double(index)) { [weak self] in
                guard let self else { return group.leave() }
                self.singleSample(host: host, port: port, rung: endpoint.rung) { rtt in
                    collector.add(rtt)
                    group.leave()
                }
            }
        }

        group.notify(queue: queue) {
            let rtts = collector.successes()
            let attempted = Double(self.samples)
            guard !rtts.isEmpty else {
                return completion(ServerProbe(rttMs: .infinity, lossFraction: 1))
            }
            let mean = rtts.reduce(0, +) / Double(rtts.count)
            let jitter = rtts.count > 1
                ? rtts.map { abs($0 - mean) }.reduce(0, +) / Double(rtts.count)
                : 0
            completion(ServerProbe(rttMs: mean,
                                   lossFraction: (attempted - Double(rtts.count)) / attempted,
                                   jitterMs: jitter))
        }
    }

    private func singleSample(host: NWEndpoint.Host, port: NWEndpoint.Port, rung: ProtocolRung,
                              completion: @escaping @Sendable (Double?) -> Void) {
        // UDP rungs get a TCP-connect measurement to the same host when possible;
        // for a pure UDP endpoint the handshake itself is the only honest signal,
        // so we measure the time to a first response instead of pretending.
        let parameters: NWParameters = rung.isUDP ? .udp : .tcp
        parameters.prohibitedInterfaceTypes = [.other]
        let connection = NWConnection(host: host, port: port, using: parameters)
        let start = DispatchTime.now()
        let finished = Once()

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ms = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000
                if finished.claim() { connection.cancel(); completion(ms) }
            case .failed, .cancelled:
                if finished.claim() { completion(nil) }
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            if finished.claim() { connection.cancel(); completion(nil) }
        }
    }

    private final class Once: @unchecked Sendable {
        private var done = false
        private let lock = NSLock()
        func claim() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }

    private final class SampleCollector: @unchecked Sendable {
        private var values: [Double?] = []
        private let lock = NSLock()
        func add(_ v: Double?) { lock.lock(); values.append(v); lock.unlock() }
        func successes() -> [Double] { lock.lock(); defer { lock.unlock() }; return values.compactMap { $0 } }
    }

    private final class Collector: @unchecked Sendable {
        private var results: [Result] = []
        private let lock = NSLock()
        func add(_ r: Result) { lock.lock(); results.append(r); lock.unlock() }
        func all() -> [Result] { lock.lock(); defer { lock.unlock() }; return results }
    }
}
