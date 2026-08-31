import Foundation

/// Keepalive is the main idle-battery lever (vault 08-Roaming/Keepalive-Interval-Vs-Battery).
public enum KeepalivePolicy {
    /// Returns seconds, or nil for "on demand only" (Low Power Mode).
    public static func interval(isExpensive: Bool, isLowPowerMode: Bool, userActive: Bool) -> Int? {
        if isLowPowerMode { return nil }
        if !userActive { return 60 }
        return isExpensive ? 20 : 25
    }
}
