#if os(macOS)
import Foundation
import SweepVPNCore

/// Points the whole Mac's SOCKS proxy at our loopback listener, so every app
/// that honours the system proxy goes through WARP (or Tor) without being
/// configured individually.
///
/// This is a system network setting, so it needs admin rights; the app is not
/// sandboxed for exactly this reason. One password prompt per change, from
/// macOS itself — we never see or store the password.
///
/// Caveat worth knowing: a SOCKS proxy only captures apps that ask the system
/// for proxy settings. DNS still goes out normally, so names are visible to the
/// network even while the traffic itself is not.
public enum SystemProxy {

    public enum Failure: LocalizedError {
        case cancelled
        case failed(String)
        public var errorDescription: String? {
            switch self {
            case .cancelled: return "Cancelled — the system proxy was not changed."
            case .failed(let why): return why
            }
        }
    }

    /// The Wi-Fi/Ethernet service carrying the default route, by name, because
    /// `networksetup` addresses services ("Wi-Fi") rather than devices ("en0").
    static let serviceScript = """
    dev=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}'); \
    svc=$(networksetup -listnetworkserviceorder | grep -B1 "Device: $dev" | head -1 | sed 's/^([0-9]*) //'); \
    [ -n "$svc" ] || { echo "no active network service" >&2; exit 1; }
    """

    static func command(enabled: Bool, port: Int) -> String {
        if enabled {
            return serviceScript + """
            ; networksetup -setsocksfirewallproxy "$svc" 127.0.0.1 \(port) off \
            && networksetup -setsocksfirewallproxystate "$svc" on
            """
        }
        return serviceScript + """
        ; networksetup -setsocksfirewallproxystate "$svc" off
        """
    }

    /// Blocking: shows the standard macOS admin prompt.
    public static func set(enabled: Bool, port: Int) throws {
        let shell = command(enabled: enabled, port: port)
        let escaped = shell
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        if let error {
            // -128 is the user dismissing the password prompt, which is a
            // choice, not a fault, and must not be reported as a failure.
            let code = error[NSAppleScript.errorNumber] as? Int ?? 0
            EventLog.shared.record(phase: "systemProxy", level: .warn, kind: "failed",
                                   detail: "code \(code)")
            throw code == -128 ? Failure.cancelled
                : Failure.failed((error[NSAppleScript.errorMessage] as? String)
                                 ?? "Could not change the system proxy.")
        }
        EventLog.shared.record(phase: "systemProxy", kind: enabled ? "enabled" : "disabled",
                               detail: "127.0.0.1:\(port)")
    }

    /// Whether the system SOCKS proxy is on and pointed at `port` on loopback.
    public static func isEnabled(port: Int) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", serviceScript + "; networksetup -getsocksfirewallproxy \"$svc\""]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        guard (try? p.run()) != nil else { return false }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let out = String(data: data, encoding: .utf8) ?? ""
        return out.contains("Enabled: Yes") && out.contains("Port: \(port)")
    }
}
#endif
