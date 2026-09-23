import Foundation

/// Application Support, or the home directory if the search fails.
///
/// `urls(for:in:)` returning empty is not supposed to happen, but two of the
/// three callers run inside the iOS packet-tunnel extension, where a trap is
/// not a crash report — it is the tunnel vanishing with no explanation.
enum SupportDirectory {
    static var base: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory())
                .appendingPathComponent("Library/Application Support", isDirectory: true)
    }
}
