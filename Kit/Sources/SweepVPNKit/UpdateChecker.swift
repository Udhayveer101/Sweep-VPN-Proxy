#if os(macOS)
import Foundation
import CryptoKit
import CoreServices

/// Finds, downloads and verifies a newer build from the project's GitHub
/// releases, so the app does not depend on the user visiting the repo.
///
/// Deliberately small: there is no appcast to host, no signing key to manage
/// beyond the Developer ID the DMG already carries, and no background daemon.
/// The releases API is the feed, the published `.sha256` is the integrity
/// check, and the app inside the notarised DMG replaces the running one.
public struct UpdateChecker: @unchecked Sendable {

    public struct Update: Sendable, Equatable {
        public let version: String
        public let notes: String
        public let asset: URL
        public let digest: URL
        /// Bytes, from the feed; 0 when it did not say.
        public var size: Int = 0
    }

    public enum UpdateError: Error, Equatable {
        case transport
        case noAsset
        case digestMismatch
        case untrustedSignature
        case noSpace
    }

    /// Both products publish into one release list, so `latest` is whichever
    /// was tagged last - often the Windows one. Read the list and filter by
    /// tag prefix instead.
    static let feed = URL(string:
        "https://api.github.com/repos/Udhayveer101/Sweep-VPN-Proxy/releases?per_page=30")!

    public static let snoozeKey = "updateSnoozeUntil"
    public static let snoozeInterval: TimeInterval = 24 * 3600
    public static let failedVersionKey = "updateFailedVersion"

    let current: String
    let tagPrefix: String
    let session: URLSession
    // UserDefaults is thread-safe but not Sendable, hence @unchecked above.
    let defaults: UserDefaults

    public init(current: String = Bundle.main.shortVersion,
                tagPrefix: String = "v",
                session: URLSession = .shared,
                defaults: UserDefaults = .standard) {
        self.current = current
        self.tagPrefix = tagPrefix
        self.session = session
        self.defaults = defaults
    }

    // MARK: - Checking

    /// `nil` means "nothing to offer": up to date, snoozed, or offline. Being
    /// offline is not an error the user needs to see.
    public func check(force: Bool = false, now: Date = Date()) async -> Update? {
        if !force, let until = defaults.object(forKey: Self.snoozeKey) as? Date, until > now {
            return nil
        }
        guard let releases = try? await fetchReleases() else { return nil }
        let found = Self.pick(from: releases, newerThan: current, tagPrefix: tagPrefix)
        // A version that already failed to start here is not offered again on
        // its own: that is how an updater ends up restarting the app every day.
        // "Check for updates" still finds it, and a later release clears it.
        if !force, let found, found.version == defaults.string(forKey: Self.failedVersionKey) {
            return nil
        }
        return found
    }

    public func snooze(now: Date = Date()) {
        defaults.set(now.addingTimeInterval(Self.snoozeInterval), forKey: Self.snoozeKey)
    }

    private func fetchReleases() async throws -> [Release] {
        var request = URLRequest(url: Self.feed)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 20
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw UpdateError.transport
        }
        return try JSONDecoder().decode([Release].self, from: data)
    }

    // MARK: - Feed shape

    struct Release: Decodable {
        let tag_name: String
        let body: String?
        let draft: Bool?
        let prerelease: Bool?
        let assets: [Asset]
        struct Asset: Decodable { let name: String; let browser_download_url: URL; var size: Int? }
    }

    /// The newest release whose tag carries our prefix and beats `current`.
    /// The prefix is what keeps the macOS app from offering itself a
    /// `windows-v*` build, since both live in the same list.
    static func pick(from releases: [Release], newerThan current: String,
                     tagPrefix: String) -> Update? {
        var best: Update?
        var bestVersion = current
        for release in releases where release.draft != true && release.prerelease != true {
            guard release.tag_name.hasPrefix(tagPrefix) else { continue }
            let version = String(release.tag_name.dropFirst(tagPrefix.count))
            // A `windows-v1.4.0` tag starts with "v"? No - but "v1" vs
            // "version-x" would, so require the remainder to look numeric.
            guard let first = version.first, first.isNumber else { continue }
            guard isNewer(version, than: bestVersion) else { continue }
            guard let asset = release.assets.first(where: { !$0.name.hasSuffix(".sha256") && isInstaller($0.name) }),
                  let digest = release.assets.first(where: { $0.name == asset.name + ".sha256" })
            else { continue }
            bestVersion = version
            best = Update(version: version, notes: release.body ?? "",
                          asset: asset.browser_download_url,
                          digest: digest.browser_download_url, size: asset.size ?? 0)
        }
        return best
    }

    private static func isInstaller(_ name: String) -> Bool {
        name.hasSuffix(".dmg") || name.hasSuffix(".exe")
    }

    /// Lexicographic compare on the numeric components. Good enough for the
    /// `1.4.0` tags this project ships; anything unparsable sorts lowest so a
    /// malformed tag can never look like an upgrade.
    static func semver(_ s: String) -> [Int] {
        s.split(whereSeparator: { $0 == "." || $0 == "-" }).map { Int($0) ?? -1 }
    }

    /// Array is not Comparable in the stdlib, so compare the components by
    /// hand; a missing component counts as 0 ("1.4" == "1.4.0").
    static func isNewer(_ lhs: String, than rhs: String) -> Bool {
        let a = semver(lhs), b = semver(rhs)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    // MARK: - Downloading

    public static var cacheDirectory: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SweepVPN/updates", isDirectory: true)
    }

    /// Downloads the installer and checks it against the published digest.
    /// A mismatch deletes the file and throws: an unverified DMG is never
    /// handed to the user, even though it would also be caught by Gatekeeper.
    public func download(_ update: Update) async throws -> URL {
        let dir = Self.cacheDirectory
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let destination = dir.appendingPathComponent(update.asset.lastPathComponent)
        // The image, the copy staged beside the app and the old app kept for
        // rollback all exist at once. Refuse now rather than fail half-way.
        let need = Int64(update.size) * 4
        for volume in [dir, Bundle.main.bundleURL.deletingLastPathComponent()] {
            if let free = try? volume.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
                .volumeAvailableCapacityForImportantUsage, free < need {
                throw UpdateError.noSpace
            }
        }

        let (payload, response) = try await session.data(from: update.asset)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.transport }
        let (digestData, digestResponse) = try await session.data(from: update.digest)
        guard (digestResponse as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.transport }

        let want = Self.expectedDigest(from: digestData)
        let got = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard let want, want == got else {
            try? FileManager.default.removeItem(at: destination)
            throw UpdateError.digestMismatch
        }
        try payload.write(to: destination, options: .atomic)
        // This app is not sandboxed, so nothing marks the file as downloaded
        // and Gatekeeper would never assess it. Mark it the way a browser would.
        var url = destination
        var values = URLResourceValues()
        values.quarantineProperties = [kLSQuarantineAgentNameKey as String: "Sweep VPN",
                                       kLSQuarantineTypeKey as String: kLSQuarantineTypeWebDownload as String]
        try? url.setResourceValues(values)
        return destination
    }

    /// The team every Sweep release is signed by. The digest comes from the
    /// same release as the DMG, so it only proves the download is intact; this
    /// proves the app inside was built and signed by us.
    static let releaseTeam = "P66SB4MX92"

    /// `shasum -a 256` writes "<hex>  <filename>".
    static func expectedDigest(from data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let hex = text.split(whereSeparator: \.isWhitespace).first.map(String.init)?.lowercased()
        guard let hex, hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        return hex
    }

    static func signedByUs(_ app: URL) -> Bool {
        let check = Process()
        check.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        check.arguments = ["--verify", "--deep", "--strict",
                           "-R=anchor apple generic and certificate leaf[subject.OU] = \"\(releaseTeam)\"",
                           app.path]
        check.standardOutput = FileHandle.nullDevice
        check.standardError = FileHandle.nullDevice
        guard (try? check.run()) != nil else { return false }
        check.waitUntilExit()
        return check.terminationStatus == 0
    }

    @discardableResult
    private static func run(_ tool: String, _ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return -1 }
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// Attaches the DMG and returns its mount point and the app inside,
    /// detaching again if anything on it is not signed by us.
    private func mountVerified(_ dmg: URL) throws -> (mount: String, app: URL) {
        let attach = Process()
        attach.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        attach.arguments = ["attach", "-nobrowse", "-noverify", dmg.path]
        let pipe = Pipe()
        attach.standardOutput = pipe
        // A licence prompt would wait on stdin forever; with none it declines.
        attach.standardInput = FileHandle.nullDevice
        try attach.run()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        attach.waitUntilExit()

        // "…  /Volumes/Sweep VPN" - the mount point is the tail of the last line.
        let mount = out.split(whereSeparator: \.isNewline)
            .compactMap { line -> String? in
                guard let range = line.range(of: "/Volumes/") else { return nil }
                return String(line[range.lowerBound...]).trimmingCharacters(in: .whitespaces)
            }.last

        guard let mount else { throw UpdateError.transport }
        let apps = ((try? FileManager.default.contentsOfDirectory(atPath: mount)) ?? [])
            .filter { $0.hasSuffix(".app") }
            .map { URL(fileURLWithPath: mount).appendingPathComponent($0) }
        guard let app = apps.first, apps.allSatisfy(Self.signedByUs) else {
            Self.run("/usr/bin/hdiutil", ["detach", "-quiet", mount])
            throw UpdateError.untrustedSignature
        }
        return (mount, app)
    }

    /// The fallback installer: mount the DMG and put it in front of the user.
    public func reveal(_ dmg: URL) throws {
        let (mount, _) = try mountVerified(dmg)
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = [mount]
        try open.run()
    }

    // MARK: - Replacing the running app

    /// Where the verified copy waits for the running app to quit. A sibling of
    /// the bundle, so the swap is a rename within one volume.
    static func stagingURL(for bundle: URL) -> URL {
        let name = bundle.deletingPathExtension().lastPathComponent
        return bundle.deletingLastPathComponent().appendingPathComponent(".\(name).update.app")
    }

    /// Copies the app out of the DMG to sit beside the running bundle, ready
    /// for `swapAfterExit`. `nil` means this copy cannot replace itself - it is
    /// running translocated or from a folder the user cannot write - and the
    /// caller should fall back to `reveal`.
    ///
    /// The copy is checked twice: our team signed it, and Gatekeeper accepts
    /// it (notarised). Only then is the quarantine flag removed, which is what
    /// lets it relaunch without a "downloaded from the internet" prompt.
    public func stage(_ dmg: URL, replacing bundle: URL = Bundle.main.bundleURL) throws -> URL? {
        let fm = FileManager.default
        guard bundle.pathExtension == "app", !bundle.path.contains("/AppTranslocation/"),
              fm.isWritableFile(atPath: bundle.deletingLastPathComponent().path) else { return nil }
        let (mount, app) = try mountVerified(dmg)
        defer { Self.run("/usr/bin/hdiutil", ["detach", "-quiet", mount]) }

        let staged = Self.stagingURL(for: bundle)
        try? fm.removeItem(at: staged)
        guard Self.run("/usr/bin/ditto", [app.path, staged.path]) == 0,
              Self.signedByUs(staged),
              Self.run("/usr/sbin/spctl", ["--assess", "--type", "execute", staged.path]) == 0
        else {
            try? fm.removeItem(at: staged)
            throw UpdateError.untrustedSignature
        }
        Self.run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", staged.path])
        return staged
    }

    /// Waits for the app to exit, renames the old bundle aside, renames the
    /// staged one into place and launches it. The old bundle is kept until the
    /// new app writes `confirmed` (see `finishPendingUpdate`); if it never
    /// does, the old bundle goes back, is relaunched, and `failed` says why.
    /// There is an app at the path on every exit.
    /// Arguments: pid, bundle, staged, opener, state directory, ticks (0.2s)
    /// to wait for the confirmation.
    static let swapScript = #"""
        pid=$1 cur=$2 new=$3 opener=$4 state=$5 ticks=$6 old="$2.old" n=0
        fail() { echo "$1" > "$state/failed"; rm -rf "$new"; exec "$opener" "$cur"; }
        while kill -0 "$pid" 2>/dev/null; do
          n=$((n+1)); [ $n -gt 300 ] && { echo "Sweep VPN did not quit." > "$state/failed"; rm -rf "$new"; exit 1; }
          sleep 0.2
        done
        rm -rf "$old"
        mv "$cur" "$old" || fail "macOS did not allow the installed app to be replaced."
        mv "$new" "$cur" || { mv "$old" "$cur"; fail "The new version could not be moved into place."; }
        "$opener" "$cur"
        n=0
        while [ ! -f "$state/confirmed" ] && [ $n -lt "$ticks" ]; do n=$((n+1)); sleep 0.2; done
        if [ -f "$state/confirmed" ]; then rm -rf "$old"; rm -f "$state/confirmed"; exit 0; fi
        pkill -f "$cur/Contents/MacOS/" 2>/dev/null; sleep 1
        rm -rf "$cur.failed"
        mv "$cur" "$cur.failed" && mv "$old" "$cur" && rm -rf "$cur.failed"
        fail "The new version did not start, so the previous one was restored."
        """#

    /// How long the new version has to say it started: 45s.
    public static let confirmTicks = 225

    /// Starts the shell that performs the swap once `pid` is gone, and leaves
    /// `pending` so the next launch knows an update was in flight. The caller
    /// then quits normally, so the usual quit-time cleanup (system proxy,
    /// gaming-mode routes) runs before the bundle is touched.
    @discardableResult
    public static func swapAfterExit(staged: URL, version: String,
                                     bundle: URL = Bundle.main.bundleURL,
                                     pid: Int32 = ProcessInfo.processInfo.processIdentifier,
                                     opener: String = "/usr/bin/open",
                                     state: URL = cacheDirectory,
                                     ticks: Int = confirmTicks) throws -> Process {
        let fm = FileManager.default
        try fm.createDirectory(at: state, withIntermediateDirectories: true)
        for name in ["confirmed", "failed"] { try? fm.removeItem(at: state.appendingPathComponent(name)) }
        try version.write(to: state.appendingPathComponent("pending"), atomically: true, encoding: .utf8)
        let swap = Process()
        swap.executableURL = URL(fileURLWithPath: "/bin/sh")
        swap.arguments = ["-c", swapScript, "sh", String(pid), bundle.path, staged.path, opener,
                          state.path, String(ticks)]
        swap.standardInput = FileHandle.nullDevice
        swap.standardOutput = FileHandle.nullDevice
        swap.standardError = FileHandle.nullDevice
        try swap.run()
        return swap
    }

    public enum Outcome: Equatable, Sendable {
        case updated(String)
        case failed(version: String, reason: String)
    }

    /// Call once at launch. If the previous run started an update, this is
    /// where it ends: the new version confirms it is running (which lets the
    /// swap script delete the old bundle), or the restored old version learns
    /// why it is still here and stops offering that release by itself.
    public func finishPendingUpdate(state: URL = cacheDirectory) -> Outcome? {
        let fm = FileManager.default
        let pending = state.appendingPathComponent("pending")
        let failed = state.appendingPathComponent("failed")
        guard let version = (try? String(contentsOf: pending, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        try? fm.removeItem(at: pending)
        if version == current {
            fm.createFile(atPath: state.appendingPathComponent("confirmed").path, contents: nil)
            defaults.removeObject(forKey: Self.failedVersionKey)
            // The images are only needed until the version they hold is running.
            for file in (try? fm.contentsOfDirectory(at: state, includingPropertiesForKeys: nil)) ?? []
            where file.pathExtension == "dmg" { try? fm.removeItem(at: file) }
            return .updated(version)
        }
        let reason = (try? String(contentsOf: failed, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        try? fm.removeItem(at: failed)
        defaults.set(version, forKey: Self.failedVersionKey)
        return .failed(version: version, reason: reason ?? "The update did not finish.")
    }
}

extension Bundle {
    public var shortVersion: String {
        (object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.0.0"
    }
}
#endif
