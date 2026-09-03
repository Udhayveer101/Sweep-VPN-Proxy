import Foundation

/// The shared app group, resolved for the platform this build is running on.
///
/// # Why this is not a constant
///
/// macOS and iOS disagree about the shape of an app group identifier. On iOS a
/// bare `group.` identifier is correct. On macOS a sandboxed app's group must be
/// prefixed with the team identifier — an unprefixed group still gets a
/// container created for it, but the system cannot attribute that container to
/// the team that signed the app. The observable symptom is the
/// "would like to access data from other apps" consent dialog reappearing on
/// every launch and for every process that touches the group, because there is
/// no team-backed group entitlement for the grant to be recorded against.
///
/// The prefix is not compiled in: it is substituted into each bundle's
/// Info.plist at build time from `DEVELOPMENT_TEAM`, so the team identifier
/// lives in the project file rather than in source. `Bundle.main` is the
/// extension when this runs inside the extension, which is what makes the two
/// processes resolve the same string without sharing any state to do it.
public enum AppGroupID {
    static let base = "group.com.sweep.vpn"

    /// Falls back to the unprefixed group so a build without the Info.plist key
    /// keeps working against an existing container instead of failing to find
    /// any group at all.
    public static let resolved: String = {
        #if os(macOS)
        if let value = Bundle.main.object(forInfoDictionaryKey: "SweepAppGroup") as? String,
           !value.isEmpty, !value.hasPrefix("$(") {
            return value
        }
        #endif
        return base
    }()
}
