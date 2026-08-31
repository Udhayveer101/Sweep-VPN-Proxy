import Foundation

/// App <-> extension messages, carried by NETunnelProviderSession.sendProviderMessage.
/// The extension is authoritative; the app is a remote control + viewer.
public enum AppToProvider: Codable, Sendable, Equatable {
    case getStatus
    case setPreference(ProtocolPreference)
    case setSecurityOptions(SecurityPolicyOptions)
    case reconnect
    case exportDiagnostics
}

public struct ProviderStatus: Codable, Sendable, Equatable {
    public var state: TunnelState
    public var serverName: String?
    public var rung: ProtocolRung?
    public var connectedSince: Date?
    public var rttMs: Double?
    public var killSwitchArmed: Bool
    public var pqHybridActive: Bool
    public init(state: TunnelState, serverName: String?, rung: ProtocolRung?, connectedSince: Date?,
                rttMs: Double?, killSwitchArmed: Bool, pqHybridActive: Bool) {
        self.state = state; self.serverName = serverName; self.rung = rung
        self.connectedSince = connectedSince; self.rttMs = rttMs
        self.killSwitchArmed = killSwitchArmed; self.pqHybridActive = pqHybridActive
    }
}

public enum ProviderToApp: Codable, Sendable, Equatable {
    case status(ProviderStatus)
    case diagnostics([DiagnosticEvent])
    case failed(TunnelErrorKind)
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
