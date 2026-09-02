#if os(macOS)
import Foundation
import Network

/// A loopback SOCKS5 + HTTP-CONNECT listener.
///
/// Two jobs. It lets individual apps opt into the tunnel by pointing at a proxy
/// instead of routing the whole system, and — with `.tor` as the upstream — it is
/// how ordinary apps reach Tor at all, since they speak SOCKS but know nothing
/// about circuits.
///
/// Bound to 127.0.0.1 only. A proxy reachable from the LAN is an open relay, and
/// this one can egress through the VPN or Tor, so binding it wider would let any
/// device on the network borrow both.
public final class LocalProxy: @unchecked Sendable {

    public enum Upstream: Equatable, Sendable {
        /// Dial the destination directly. With the tunnel up this still egresses
        /// through the VPN — the tunnel is a route, not a proxy.
        case direct
        /// Chain through another SOCKS5 proxy, i.e. Tor.
        case socks5(host: String, port: Int)
    }

    public enum State: Equatable, Sendable {
        case stopped
        case listening(port: Int)
        case failed(String)
    }

    public private(set) var state: State = .stopped {
        didSet { if state != oldValue { onState?(state) } }
    }

    private let port: NWEndpoint.Port
    private var upstream: Upstream
    private var listener: NWListener?
    private var onState: (@Sendable (State) -> Void)?
    private let queue = DispatchQueue(label: "sweep.localproxy")

    public init?(port: Int = 1080, upstream: Upstream = .direct) {
        guard let p = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0) else { return nil }
        self.port = p
        self.upstream = upstream
    }

    public func start(upstream: Upstream? = nil,
                      onState: @escaping @Sendable (State) -> Void) {
        self.onState = onState
        if let upstream { self.upstream = upstream }
        stop()
        do {
            let params = NWParameters.tcp
            params.requiredInterfaceType = .loopback
            params.allowLocalEndpointReuse = true
            let l = try NWListener(using: params, on: port)
            l.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
            l.stateUpdateHandler = { [weak self] s in
                guard let self else { return }
                switch s {
                case .ready: self.state = .listening(port: Int(self.port.rawValue))
                case .failed(let e): self.state = .failed(e.localizedDescription)
                case .cancelled: self.state = .stopped
                default: break
                }
            }
            l.start(queue: queue)
            listener = l
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    public func stop() {
        listener?.cancel()
        listener = nil
    }

    // MARK: - Connection handling

    private func accept(_ client: NWConnection) {
        client.start(queue: queue)
        // One byte distinguishes the two protocols: SOCKS5 always opens with 0x05,
        // an HTTP proxy request always opens with an ASCII method letter.
        receive(client, min: 1, max: 1) { [weak self] first in
            guard let self, let first, let byte = first.first else { client.cancel(); return }
            if byte == 0x05 {
                self.socksGreeting(client)
            } else {
                self.httpConnect(client, firstByte: byte)
            }
        }
    }

    /// SOCKS5 greeting: we have already eaten the version byte.
    private func socksGreeting(_ client: NWConnection) {
        receive(client, min: 1, max: 1) { [weak self] countData in
            guard let self, let n = countData?.first, n > 0 else { client.cancel(); return }
            self.receive(client, min: Int(n), max: Int(n)) { methods in
                guard let methods else { client.cancel(); return }
                // Only "no authentication" is offered. This listener is loopback-only,
                // so a password would protect nothing that the bind address does not.
                guard methods.contains(0x00) else {
                    client.send(content: Data([0x05, 0xFF]), completion: .contentProcessed { _ in
                        client.cancel()
                    })
                    return
                }
                client.send(content: Data([0x05, 0x00]), completion: .contentProcessed { [weak self] _ in
                    self?.socksRequest(client)
                })
            }
        }
    }

    private func socksRequest(_ client: NWConnection) {
        // VER CMD RSV ATYP
        receive(client, min: 4, max: 4) { [weak self] header in
            guard let self, let header, header.count == 4 else { client.cancel(); return }
            guard header[1] == 0x01 else {          // CONNECT only; no BIND/UDP ASSOCIATE
                self.socksFail(client, code: 0x07)  // command not supported
                return
            }
            let readAddress: (@escaping (String?) -> Void) -> Void
            switch header[3] {
            case 0x01:                                   // IPv4
                readAddress = { done in
                    self.receive(client, min: 4, max: 4) { d in
                        done(d.map { $0.map(String.init).joined(separator: ".") })
                    }
                }
            case 0x03:                                   // domain name
                readAddress = { done in
                    self.receive(client, min: 1, max: 1) { lenData in
                        guard let n = lenData?.first, n > 0 else { done(nil); return }
                        self.receive(client, min: Int(n), max: Int(n)) { d in
                            done(d.flatMap { String(data: $0, encoding: .utf8) })
                        }
                    }
                }
            case 0x04:                                   // IPv6
                readAddress = { done in
                    self.receive(client, min: 16, max: 16) { d in
                        guard let d else { done(nil); return }
                        let groups = stride(from: 0, to: 16, by: 2).map {
                            String(format: "%02x%02x", d[d.startIndex + $0], d[d.startIndex + $0 + 1])
                        }
                        done(groups.joined(separator: ":"))
                    }
                }
            default:
                self.socksFail(client, code: 0x08)       // address type not supported
                return
            }

            readAddress { host in
                guard let host else { self.socksFail(client, code: 0x01); return }
                self.receive(client, min: 2, max: 2) { portData in
                    guard let portData, portData.count == 2 else {
                        self.socksFail(client, code: 0x01); return
                    }
                    let port = Int(portData[portData.startIndex]) << 8
                        | Int(portData[portData.startIndex + 1])
                    self.connectUpstream(host: host, port: port) { remote in
                        guard let remote else { self.socksFail(client, code: 0x05); return }
                        // Success. The bound-address field is not meaningful for a
                        // CONNECT reply, so report 0.0.0.0:0 as most proxies do.
                        let reply = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        client.send(content: reply, completion: .contentProcessed { _ in
                            self.splice(client, remote)
                        })
                    }
                }
            }
        }
    }

    private func socksFail(_ client: NWConnection, code: UInt8) {
        let reply = Data([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        client.send(content: reply, completion: .contentProcessed { _ in client.cancel() })
    }

    /// Minimal HTTP CONNECT, for apps that only speak an HTTP proxy.
    private func httpConnect(_ client: NWConnection, firstByte: UInt8) {
        readHTTPHead(client, accumulated: Data([firstByte])) { [weak self] head, leftover in
            guard let self, let head,
                  let line = String(data: head, encoding: .utf8)?
                    .split(separator: "\r\n").first else { client.cancel(); return }
            let parts = line.split(separator: " ")
            guard parts.count >= 2, parts[0].uppercased() == "CONNECT" else {
                // Only tunnelling is supported; plain proxied GET would require
                // rewriting requests, and every modern client uses CONNECT for TLS.
                self.httpFail(client, "405 Method Not Allowed")
                return
            }
            let target = parts[1]
            guard let colon = target.lastIndex(of: ":"),
                  let port = Int(target[target.index(after: colon)...]) else {
                self.httpFail(client, "400 Bad Request")
                return
            }
            let host = String(target[target.startIndex..<colon])
            self.connectUpstream(host: host, port: port) { remote in
                guard let remote else { self.httpFail(client, "502 Bad Gateway"); return }
                let ok = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
                client.send(content: ok, completion: .contentProcessed { _ in
                    // A client that pipelined payload behind the CONNECT already
                    // had those bytes read into the header buffer. Forward them
                    // before splicing, or they are silently lost.
                    if !leftover.isEmpty {
                        remote.send(content: leftover, completion: .contentProcessed { _ in })
                    }
                    self.splice(client, remote)
                })
            }
        }
    }

    private func httpFail(_ client: NWConnection, _ status: String) {
        let body = Data("HTTP/1.1 \(status)\r\nContent-Length: 0\r\n\r\n".utf8)
        client.send(content: body, completion: .contentProcessed { _ in client.cancel() })
    }

    /// Reads until the end of the header block, with a hard cap so a client that
    /// never sends CRLFCRLF cannot make us buffer without bound.
    /// Returns the header block and any bytes that arrived behind it.
    private func readHTTPHead(_ conn: NWConnection, accumulated: Data,
                              limit: Int = 8192,
                              done: @escaping (Data?, Data) -> Void) {
        let terminator = Data("\r\n\r\n".utf8)
        if let r = accumulated.range(of: terminator) {
            return done(accumulated[..<r.lowerBound], accumulated[r.upperBound...])
        }
        guard accumulated.count < limit else { return done(nil, Data()) }
        receive(conn, min: 1, max: 1024) { [weak self] chunk in
            guard let self, let chunk, !chunk.isEmpty else { return done(nil, Data()) }
            self.readHTTPHead(conn, accumulated: accumulated + chunk, limit: limit, done: done)
        }
    }

    // MARK: - Upstream

    private func connectUpstream(host: String, port: Int,
                                 done: @escaping (NWConnection?) -> Void) {
        switch upstream {
        case .direct:
            dial(host: host, port: port) { done($0) }
        case .socks5(let proxyHost, let proxyPort):
            dial(host: proxyHost, port: proxyPort) { [weak self] conn in
                guard let self, let conn else { return done(nil) }
                self.socksClientHandshake(conn, host: host, port: port) { ok in
                    if ok { done(conn) } else { conn.cancel(); done(nil) }
                }
            }
        }
    }

    /// Fires its callback exactly once. `stateUpdateHandler` is called repeatedly
    /// and can reach `.failed` after `.ready`; resuming a dial twice would hand the
    /// same connection to two spliced pairs.
    private final class DialOnce: @unchecked Sendable {
        private var fired = false
        private let lock = NSLock()
        private let body: (NWConnection?) -> Void
        init(_ body: @escaping (NWConnection?) -> Void) { self.body = body }
        func fire(_ conn: NWConnection?) {
            lock.lock()
            if fired { lock.unlock(); return }
            fired = true
            lock.unlock()
            body(conn)
        }
    }

    private func dial(host: String, port: Int, done: @escaping (NWConnection?) -> Void) {
        guard let p = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0) else { return done(nil) }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        let once = DialOnce(done)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:              once.fire(conn)
            case .failed, .cancelled: once.fire(nil)
            default: break
            }
        }
        conn.start(queue: queue)
    }

    /// Speak SOCKS5 *as a client* to the upstream proxy (Tor). The hostname is
    /// passed through unresolved so the name is resolved at the exit, not here —
    /// resolving locally would leak the destination to the local DNS server.
    private func socksClientHandshake(_ conn: NWConnection, host: String, port: Int,
                                      done: @escaping (Bool) -> Void) {
        conn.send(content: Data([0x05, 0x01, 0x00]), completion: .contentProcessed { [weak self] _ in
            guard let self else { return done(false) }
            self.receive(conn, min: 2, max: 2) { greeting in
                guard let greeting, greeting.count == 2,
                      greeting[greeting.startIndex] == 0x05,
                      greeting[greeting.startIndex + 1] == 0x00 else { return done(false) }
                var req = Data([0x05, 0x01, 0x00, 0x03])
                let hostBytes = Array(host.utf8)
                guard hostBytes.count <= 255 else { return done(false) }
                req.append(UInt8(hostBytes.count))
                req.append(contentsOf: hostBytes)
                req.append(UInt8((port >> 8) & 0xFF))
                req.append(UInt8(port & 0xFF))
                conn.send(content: req, completion: .contentProcessed { _ in
                    // VER REP RSV ATYP, then a variable bound address we discard.
                    self.receive(conn, min: 4, max: 4) { reply in
                        guard let reply, reply.count == 4,
                              reply[reply.startIndex + 1] == 0x00 else { return done(false) }
                        let trailing: Int
                        switch reply[reply.startIndex + 3] {
                        case 0x01: trailing = 4 + 2
                        case 0x04: trailing = 16 + 2
                        case 0x03:
                            self.receive(conn, min: 1, max: 1) { lenData in
                                guard let n = lenData?.first else { return done(false) }
                                self.receive(conn, min: Int(n) + 2, max: Int(n) + 2) { _ in done(true) }
                            }
                            return
                        default: return done(false)
                        }
                        self.receive(conn, min: trailing, max: trailing) { _ in done(true) }
                    }
                })
            }
        })
    }

    // MARK: - Plumbing

    /// Copies bytes in both directions until either side closes.
    private func splice(_ a: NWConnection, _ b: NWConnection) {
        pump(from: a, to: b)
        pump(from: b, to: a)
    }

    private func pump(from: NWConnection, to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) { data, _, done, error in
            if let data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { _ in })
            }
            if done || error != nil {
                to.cancel(); from.cancel(); return
            }
            self.pump(from: from, to: to)
        }
    }

    private func receive(_ conn: NWConnection, min: Int, max: Int,
                         done: @escaping (Data?) -> Void) {
        conn.receive(minimumIncompleteLength: min, maximumLength: max) { data, _, _, error in
            done(error == nil ? data : nil)
        }
    }
}
#endif
