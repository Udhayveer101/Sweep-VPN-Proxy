#if os(macOS)
import Foundation
import Security

/// Runs one command as root.
///
/// `osascript ... with administrator privileges` shows AppleScript's own dialog,
/// which only ever takes a typed password. Authorization Services shows the
/// system's dialog instead, and that one offers Touch ID where the Mac and the
/// user's settings allow it. The right asked for is `system.privilege.admin` —
/// the same right the AppleScript path asks for, so this is a nicer prompt for
/// the same privilege, not a wider one.
///
/// `AuthorizationExecuteWithPrivileges` has been deprecated since 10.7 and the
/// Swift overlay hides it, so it is resolved at runtime. Everything here fails
/// soft: if the symbol is gone, the right is denied for any reason other than
/// the user saying no, or the call fails, the caller falls back to the osascript
/// path that shipped before. The worst case is today's behaviour.
enum Elevator {

    enum Outcome {
        case launched
        case cancelled           // the user dismissed the prompt — do not retry
        case unavailable(String) // fall back to osascript
    }

    private typealias ExecuteWithPrivileges = @convention(c) (
        AuthorizationRef,
        UnsafePointer<CChar>,
        AuthorizationFlags,
        UnsafePointer<UnsafeMutablePointer<CChar>?>,
        UnsafeMutablePointer<UnsafeMutablePointer<FILE>?>?
    ) -> OSStatus

    /// Runs `tool` with `arguments` as root. The tool is expected to daemonise
    /// itself; this does not wait for it to finish.
    static func run(tool: String, arguments: [String]) -> Outcome {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2),  // RTLD_DEFAULT
                                 "AuthorizationExecuteWithPrivileges") else {
            return .unavailable("AuthorizationExecuteWithPrivileges is not available")
        }
        let execute = unsafeBitCast(symbol, to: ExecuteWithPrivileges.self)

        var authRef: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authRef) == errAuthorizationSuccess,
              let auth = authRef else {
            return .unavailable("could not create an authorization session")
        }
        defer { AuthorizationFree(auth, []) }

        var status = errAuthorizationSuccess
        "system.privilege.admin".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            withUnsafeMutablePointer(to: &item) { itemPtr in
                var rights = AuthorizationRights(count: 1, items: itemPtr)
                // .interactionAllowed is what lets the system put up its dialog,
                // which is where Touch ID appears.
                status = AuthorizationCopyRights(auth, &rights, nil,
                                                 [.interactionAllowed, .preAuthorize, .extendRights],
                                                 nil)
            }
        }
        if status == errAuthorizationCanceled { return .cancelled }
        guard status == errAuthorizationSuccess else {
            return .unavailable("authorization denied (OSStatus \(status))")
        }

        // The C call wants a NULL-terminated argv of mutable C strings.
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) }
        argv.append(nil)
        defer { for p in argv where p != nil { free(p) } }

        let rc = tool.withCString { toolPath in
            argv.withUnsafeBufferPointer { buffer in
                execute(auth, toolPath, [], buffer.baseAddress!, nil)
            }
        }
        if rc == errAuthorizationCanceled { return .cancelled }
        guard rc == errAuthorizationSuccess else {
            return .unavailable("could not run as root (OSStatus \(rc))")
        }
        return .launched
    }
}
#endif
