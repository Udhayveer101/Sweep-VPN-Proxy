#if os(macOS)
import Foundation
import Network

/// One TCP connection, carried to its destination inside a WebSocket to the
/// Worker.
///
/// This is the general-exit mode: the Worker dials the destination itself, so
/// there is no VPN Gate relay in the path and none of what comes with one — no
/// pool, no `AUTH_FAILED`, no 62-second idle FIN, no handover. It also means no
/// packet tunnel, so no kill switch either.
///
/// Deliberately *not* `WebSocketTransport`: that stands up an `NWListener` per
/// instance and carries relay-session resume. A browser opens dozens of
/// connections at once and a listener each is the wrong shape. Same wire
/// protocol, none of the session machinery.
public final class WorkerStream: @unchecked Sendable {

    private let socket: MinimalWebSocket
    private let connection: NWConnection
    private let lock = NSLock()
    private var onData: (@Sendable (Data) -> Void)?
    private var onClose: (@Sendable () -> Void)?
    private var pending: [Data] = []
    private var closedBeforeHandler = false

    private init(socket: MinimalWebSocket, connection: NWConnection) {
        self.socket = socket
        self.connection = connection
    }

    /// The destination travels in the query, so it must be escaped. An
    /// unescaped `&` in a hostname would otherwise let the caller append a
    /// parameter of its own — a different port, for one.
    static func path(host: String, port: Int, token: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func esc(_ s: String) -> String {
            s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
        }
        // A fresh session per stream. The id keys the Durable Object, so two
        // streams sharing one would interleave their bytes into a single
        // socket. No resume: these are short and a redial is cheaper than
        // parking bytes for one.
        let session = UUID().uuidString
        return "/tcp?h=\(esc(host))&p=\(port)&t=\(esc(token))&s=\(esc(session))"
    }

    /// Dials the Worker, upgrades, and waits for the one-byte status the Worker
    /// sends once it has reached the destination: 0x01 connected, 0x00 failed.
    /// Calls back with nil on any failure along the way.
    public static func open(settings: RelayTunnelSettings,
                            host: String,
                            port: Int,
                            queue: DispatchQueue,
                            completion: @escaping @Sendable (WorkerStream?) -> Void) {
        guard let workerHost = settings.workerURL.host else { return completion(nil) }
        let workerPort = NWEndpoint.Port(rawValue: UInt16(settings.workerURL.port ?? 443)) ?? 443
        let conn = NWConnection(host: NWEndpoint.Host(workerHost),
                                port: workerPort,
                                using: .tls)

        let done = OneShot(completion)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let ws = MinimalWebSocket(
                    connection: conn,
                    host: workerHost,
                    path: path(host: host, port: port, token: settings.token))
                ws.handshake { error in
                    if error != nil { conn.cancel(); return done.fire(nil) }
                    let stream = WorkerStream(socket: ws, connection: conn)
                    // One receive loop for the life of the stream.
                    // `MinimalWebSocket.receive` *is* the loop, so it may only
                    // be started once: the status byte and the payload have to
                    // come out of the same one.
                    let status = Flag()
                    ws.receive(onMessage: { data in
                        if !status.isSet {
                            guard let first = data.first else { return }
                            status.set()
                            guard first == 0x01 else { conn.cancel(); return done.fire(nil) }
                            done.fire(stream)
                            // The Worker can pack the first payload bytes into
                            // the same frame as the status.
                            let tail = data.dropFirst()
                            if !tail.isEmpty { stream.deliver(Data(tail)) }
                            return
                        }
                        if !data.isEmpty { stream.deliver(data) }
                    }, onClose: { _ in
                        conn.cancel()
                        // Before the status byte a close is a dial failure;
                        // after it, it is the destination hanging up.
                        if !status.isSet { status.set(); return done.fire(nil) }
                        stream.deliverClose()
                    })
                }
            case .failed, .cancelled:
                done.fire(nil)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    public func send(_ data: Data) {
        guard !data.isEmpty else { return }
        socket.send(data)
    }

    /// Bytes from the destination. The status byte has already been consumed by
    /// `open`, so everything delivered here is payload.
    ///
    /// The receive loop is running before this is called, so anything that
    /// arrived in the gap is held and replayed rather than dropped.
    public func receive(onData: @escaping @Sendable (Data) -> Void,
                        onClose: @escaping @Sendable () -> Void) {
        lock.lock()
        self.onData = onData
        self.onClose = onClose
        let held = pending
        let alreadyClosed = closedBeforeHandler
        pending = []
        lock.unlock()
        for chunk in held { onData(chunk) }
        if alreadyClosed { onClose() }
    }

    public func cancel() {
        connection.cancel()
    }

    private func deliver(_ data: Data) {
        lock.lock()
        guard let handler = onData else {
            pending.append(data)
            lock.unlock()
            return
        }
        lock.unlock()
        handler(data)
    }

    private func deliverClose() {
        lock.lock()
        guard let handler = onClose else {
            closedBeforeHandler = true
            lock.unlock()
            return
        }
        lock.unlock()
        handler()
    }

    /// The status byte is read on the same serial receive loop that carries the
    /// payload, so this only has to be safe to *observe* from elsewhere.
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
        func set() { lock.lock(); value = true; lock.unlock() }
    }

    /// `stateUpdateHandler` fires repeatedly and can reach `.failed` after
    /// `.ready`; resuming a dial twice would hand one stream to two splices.
    /// Same reason `LocalProxy.DialOnce` exists.
    private final class OneShot: @unchecked Sendable {
        private var fired = false
        private let lock = NSLock()
        private let body: @Sendable (WorkerStream?) -> Void
        init(_ body: @escaping @Sendable (WorkerStream?) -> Void) { self.body = body }
        func fire(_ s: WorkerStream?) {
            lock.lock()
            if fired { lock.unlock(); return }
            fired = true
            lock.unlock()
            body(s)
        }
    }
}
#endif
