#if os(macOS)
import Foundation
import Network
import SweepVPNCore

/// A WebSocket client written out by hand, over a plain TLS connection.
///
/// # Why not `NWProtocolWebSocket`
///
/// It cannot complete a handshake with a Cloudflare Worker. Measured, on two
/// different networks, tunnel up and tunnel down, dialling by name and by
/// address, with and without an explicit `http/1.1` ALPN: the connection goes
/// `preparing` → `waiting(POSIXErrorCode 53)` and never becomes ready. The same
/// `NWConnection` construction reaches `echo.websocket.org` and reports
/// `.ready`, and `URLSessionWebSocketTask` reaches this very Worker and reads
/// its status byte — so the network, the Worker and Apple's TLS stack are all
/// fine, and the framer is not.
///
/// `URLSessionWebSocketTask` is not the way out: inside a packet tunnel
/// provider it evaluates its path against the tunnel the provider has just
/// taken over, and it resolves by name.
///
/// # Why the address, not the name
///
/// Name resolution does not work inside the blackhole. With the tunnel up, a
/// direct query to an excluded resolver answers (`dig @8.8.8.8` returns the
/// Worker's addresses) but `getaddrinfo` returns nothing: mDNSResponder follows
/// the primary service, which is the tunnel we have just blackholed. Raw TCP to
/// an excluded address succeeds. So the bring-up path may use addresses and
/// nothing else — the app resolves the Worker while it is still an ordinary
/// process and leaves the answer in the app group.
///
/// The address goes in the endpoint, the name goes in SNI and in the `Host`
/// header, so Cloudflare still routes it to our Worker.
final class MinimalWebSocket: @unchecked Sendable {

    enum WebSocketError: Error, Equatable {
        case handshakeFailed(String)
        case closed
    }

    private let connection: NWConnection
    private let host: String
    private let path: String
    private let key = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()

    /// Bytes received and not yet parsed into a frame, with a read cursor.
    ///
    /// This is a cursor and not `removeSubrange(..<n)` because this buffer is
    /// the tunnel's whole inbound path: dropping from the front of a 64 KB
    /// buffer once per frame, and copying the entire remainder into a fresh
    /// array on every parse attempt, is quadratic in the amount of data moved.
    /// At tunnel throughput that alone pins a core and caps the link long
    /// before the relay does.
    private var inbound: [UInt8] = []
    private var readIndex = 0
    /// Payload of a fragmented message, accumulated until FIN.
    private var fragment = Data()
    /// Response bytes read during the upgrade, before framing starts.
    private var handshakeBuffer = Data()

    init(connection: NWConnection, host: String, path: String) {
        self.connection = connection
        self.host = host
        self.path = path
    }

    // MARK: - Handshake

    /// Sends the upgrade request and calls back once the 101 has been read.
    ///
    /// Any bytes that arrive in the same read as the end of the headers are
    /// kept: the Worker sends its status byte the moment it has connected, and
    /// it can share a segment with the response. Dropping that tail loses the
    /// one frame the caller is waiting for.
    func handshake(completion: @escaping @Sendable (Error?) -> Void) {
        var request = "GET \(path) HTTP/1.1\r\n"
        request += "Host: \(host)\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Sec-WebSocket-Key: \(key)\r\n"
        request += "Sec-WebSocket-Version: 13\r\n\r\n"
        connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
            if let error { completion(error); return }
            self.readUntilHeadersEnd(completion)
        })
    }

    private func readUntilHeadersEnd(_ completion: @escaping @Sendable (Error?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error { completion(error); return }
            if let data { self.handshakeBuffer.append(data) }
            if isComplete && data == nil { completion(WebSocketError.closed); return }

            guard let end = Self.rangeOfHeaderTerminator(in: self.handshakeBuffer) else {
                guard self.handshakeBuffer.count < 32 * 1024 else {
                    completion(WebSocketError.handshakeFailed("no header terminator"))
                    return
                }
                self.readUntilHeadersEnd(completion)
                return
            }
            let head = String(decoding: self.handshakeBuffer[..<end.lowerBound], as: UTF8.self)
            // Anything past the headers is already frame data.
            self.inbound = [UInt8](self.handshakeBuffer[end.upperBound...])
            self.readIndex = 0
            self.handshakeBuffer = Data()
            guard head.hasPrefix("HTTP/1.1 101") || head.hasPrefix("HTTP/1.0 101") else {
                // The status line is the whole diagnosis when a Worker refuses:
                // a 426 is a missing upgrade header, a 403 a bad token, a 200
                // the mirror answering because the path was wrong.
                let status = head.split(separator: "\r\n").first.map(String.init) ?? "no status line"
                completion(WebSocketError.handshakeFailed(status))
                return
            }
            completion(nil)
        }
    }

    /// CRLF CRLF, or the bare LF LF some servers emit.
    static func rangeOfHeaderTerminator(in data: Data) -> Range<Data.Index>? {
        if let r = data.range(of: Data("\r\n\r\n".utf8)) { return r }
        return data.range(of: Data("\n\n".utf8))
    }

    // MARK: - Sending

    /// One unfragmented binary frame. Client frames are always masked.
    func send(_ payload: Data) {
        connection.send(content: Self.frame(payload), completion: .contentProcessed { _ in })
    }

    static func frame(_ payload: Data, opcode: UInt8 = 0x2) -> Data {
        var out = Data([0x80 | opcode])
        let mask = UInt8(0x80)
        switch payload.count {
        case ..<126:
            out.append(mask | UInt8(payload.count))
        case ..<65536:
            out.append(mask | 126)
            out.append(UInt8(payload.count >> 8))
            out.append(UInt8(payload.count & 0xFF))
        default:
            out.append(mask | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((payload.count >> shift) & 0xFF))
            }
        }
        let maskingKey = (0..<4).map { _ in UInt8.random(in: 0...255) }
        out.append(contentsOf: maskingKey)
        // Masked in one pass over contiguous storage. `payload.enumerated()`
        // with a per-byte `Data.append` was the send half of the same quadratic
        // cost as the receive buffer, and it ran on every packet.
        var masked = [UInt8](repeating: 0, count: payload.count)
        payload.withUnsafeBytes { raw in
            let src = raw.bindMemory(to: UInt8.self)
            for i in 0..<src.count { masked[i] = src[i] ^ maskingKey[i & 3] }
        }
        out.append(contentsOf: masked)
        return out
    }

    // MARK: - Receiving

    /// Calls `onMessage` for each complete binary/text message, and `onClose`
    /// once, when the peer closes or the connection errors.
    /// What the peer's close frame said, once one has arrived. Nil means the
    /// stream ended without one, which is a dropped TCP session rather than a
    /// close either end chose.
    private(set) var closeSummary: String?

    func receive(onMessage: @escaping @Sendable (Data) -> Void,
                 onClose: @escaping @Sendable (Error?) -> Void) {
        // Drain whatever the handshake read left over before asking for more,
        // or a status byte that shared a segment with the response would sit in
        // the buffer until the next packet arrived — which, for a peer waiting
        // on us, is never.
        if deliverBufferedFrames(onMessage: onMessage, onClose: onClose) { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error { onClose(error); return }
            if let data { self.inbound.append(contentsOf: data) }
            if isComplete && data == nil { onClose(nil); return }
            self.receive(onMessage: onMessage, onClose: onClose)
        }
    }

    /// Drop the consumed prefix, but only once it is worth a memmove.
    private func compact() {
        guard readIndex > 0 else { return }
        if readIndex == inbound.count {
            inbound.removeAll(keepingCapacity: true)
            readIndex = 0
        } else if readIndex >= 64 * 1024 {
            inbound.removeFirst(readIndex)
            readIndex = 0
        }
    }

    /// Parses every whole frame in the buffer. Returns true if the stream ended.
    private func deliverBufferedFrames(onMessage: @Sendable (Data) -> Void,
                                       onClose: @Sendable (Error?) -> Void) -> Bool {
        while let parsed = Self.parseFrame(inbound, from: readIndex) {
            readIndex += parsed.consumed
            compact()
            switch parsed.opcode {
            case 0x0, 0x1, 0x2:
                fragment.append(parsed.payload)
                if parsed.isFinal {
                    let message = fragment
                    fragment = Data()
                    onMessage(message)
                }
            case 0x8:
                // The close payload is code+reason. It is the only thing that
                // says whether the relay hung up (Worker: 1000 "eof"), the
                // Worker itself was torn down, or the stream just ended — and
                // those have three different fixes.
                if parsed.payload.count >= 2 {
                    let code = Int(parsed.payload[parsed.payload.startIndex]) << 8
                        | Int(parsed.payload[parsed.payload.startIndex + 1])
                    let reason = String(decoding: parsed.payload.dropFirst(2), as: UTF8.self)
                    closeSummary = reason.isEmpty ? "close \(code)" : "close \(code) \(reason)"
                } else {
                    closeSummary = "close, no code"
                }
                onClose(nil)
                return true
            case 0x9:
                // A pong is required, and nothing else replies to a ping now
                // that the framework's `autoReplyPing` is not in the path.
                connection.send(content: Self.frame(parsed.payload, opcode: 0xA),
                                completion: .contentProcessed { _ in })
            default:
                break   // pong, or a reserved opcode we have no business acting on
            }
        }
        return false
    }

    struct Frame: Equatable {
        var opcode: UInt8
        var isFinal: Bool
        var payload: Data
        /// Bytes of `data` this frame occupied.
        var consumed: Int
    }

    /// One frame off the front of `data`, or nil while it is still incomplete.
    ///
    /// Server-to-client frames are never masked, but a masked one is decoded
    /// rather than rejected: being strict here would turn a peer's harmless
    /// deviation into a dead tunnel.
    static func parseFrame(_ data: Data) -> Frame? {
        parseFrame([UInt8](data), from: 0)
    }

    /// One frame starting at `start`, or nil while it is still incomplete.
    /// `consumed` counts from `start`, so the caller advances a cursor rather
    /// than shifting the buffer.
    static func parseFrame(_ bytes: [UInt8], from start: Int) -> Frame? {
        let end = bytes.count
        guard end - start >= 2 else { return nil }
        let isFinal = bytes[start] & 0x80 != 0
        let opcode = bytes[start] & 0x0F
        let isMasked = bytes[start + 1] & 0x80 != 0
        var length = Int(bytes[start + 1] & 0x7F)
        var cursor = start + 2
        if length == 126 {
            guard end >= cursor + 2 else { return nil }
            length = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
            cursor += 2
        } else if length == 127 {
            guard end >= cursor + 8 else { return nil }
            length = 0
            for i in 0..<8 { length = length << 8 | Int(bytes[cursor + i]) }
            cursor += 8
        }
        var maskingKey: [UInt8] = []
        if isMasked {
            guard end >= cursor + 4 else { return nil }
            maskingKey = Array(bytes[cursor..<(cursor + 4)])
            cursor += 4
        }
        guard end >= cursor + length else { return nil }
        var payload = Data(bytes[cursor..<(cursor + length)])
        if isMasked {
            payload.withUnsafeMutableBytes { raw in
                let p = raw.bindMemory(to: UInt8.self)
                for i in 0..<p.count { p[i] ^= maskingKey[i & 3] }
            }
        }
        return Frame(opcode: opcode, isFinal: isFinal, payload: payload,
                     consumed: cursor + length - start)
    }
}
#endif
