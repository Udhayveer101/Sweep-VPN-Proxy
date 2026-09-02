import Foundation

/// App <-> extension messages, carried by NETunnelProviderSession.sendProviderMessage.
/// The extension is authoritative; the app is a remote control + viewer.
public enum AppToProvider: Codable, Sendable, Equatable {
    case getStatus
    case setPreference(ProtocolPreference)
    case setSecurityOptions(SecurityPolicyOptions)
    case reconnect
    case exportDiagnostics
    case getServers
    case selectServer(ServerID)
    /// The app changed which public relay is selected, in the shared store.
    /// The relay itself does not travel here — it is too big for a message and
    /// has to survive the extension restarting anyway.
    case relaySelectionChanged
}

public struct ProviderStatus: Codable, Sendable, Equatable {
    public var state: TunnelState
    public var serverName: String?
    public var rung: ProtocolRung?
    public var connectedSince: Date?
    public var rttMs: Double?
    public var killSwitchArmed: Bool
    public var pqHybridActive: Bool
    /// Seconds since the last completed WireGuard handshake, or nil when there
    /// has never been one. The Security panel shows this because it is the one
    /// value that proves the tunnel is live rather than merely configured — a
    /// stale handshake age is how a silently dead tunnel looks.
    public var handshakeAgeSeconds: Int64?
    public var bytesSent: UInt64
    public var bytesReceived: UInt64

    public init(state: TunnelState, serverName: String?, rung: ProtocolRung?, connectedSince: Date?,
                rttMs: Double?, killSwitchArmed: Bool, pqHybridActive: Bool,
                handshakeAgeSeconds: Int64? = nil,
                bytesSent: UInt64 = 0, bytesReceived: UInt64 = 0) {
        self.state = state; self.serverName = serverName; self.rung = rung
        self.connectedSince = connectedSince; self.rttMs = rttMs
        self.killSwitchArmed = killSwitchArmed; self.pqHybridActive = pqHybridActive
        self.handshakeAgeSeconds = handshakeAgeSeconds
        self.bytesSent = bytesSent; self.bytesReceived = bytesReceived
    }
}

public enum ProviderToApp: Codable, Sendable, Equatable {
    case status(ProviderStatus)
    case diagnostics([DiagnosticEvent])
    case servers([RankedServer])
    case failed(TunnelErrorKind)
}

/// A server plus its latest measurement, in the order the UI should show them.
public struct RankedServer: Codable, Sendable, Equatable, Identifiable {
    public var server: Server
    public var rttMs: Double?
    public var lossFraction: Double?
    public var id: ServerID { server.id }

    public init(server: Server, rttMs: Double?, lossFraction: Double?) {
        self.server = server; self.rttMs = rttMs; self.lossFraction = lossFraction
    }
}

public enum IPCCodec {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let e = JSONEncoder(); e.dateEncodingStrategy = .secondsSince1970
        return try e.encode(value)
    }
    public static func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970
        return try d.decode(type, from: data)
    }
}
