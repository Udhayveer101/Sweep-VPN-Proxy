#if os(macOS)
import Foundation
import CryptoKit

/// Finds, downloads and verifies a newer build from the project's GitHub
/// releases, so the app does not depend on the user visiting the repo.
///
/// Deliberately small: there is no appcast to host, no signing key to manage
/// beyond the Developer ID the DMG already carries, and no background daemon.
/// The releases API is the feed, the published `.sha256` is the integrity
/// check, and the notarised DMG is the installer.
public struct UpdateChecker: @unchecked Sendable {

    public struct Update: Sendable, Equatable {
        public let version: String
        public let notes: String
        public let asset: URL
        public let digest: URL
    }

    public enum UpdateError: Error, Equatable {
        case transport
        case noAsset
        case digestMismatch
    }

    /// Both products publish into one release list, so `latest` is whichever
    /// was tagged last - often the Windows one. Read the list and filter by
    /// tag prefix instead.
    static let feed = URL(string:
        "https://api.github.com/repos/Udhayveer101/Sweep-VPN-Proxy/releases?per_page=30")!

    public static let snoozeKey = "updateSnoozeUntil"
    public static let snoozeInterval: TimeInterval = 24 * 3600

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
        return Self.pick(from: releases, newerThan: current, tagPrefix: tagPrefix)
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
        struct Asset: Decodable { let name: String; let browser_download_url: URL }
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
                          digest: digest.browser_download_url)
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
        return destination
    }

    /// `shasum -a 256` writes "<hex>  <filename>".
    static func expectedDigest(from data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let hex = text.split(whereSeparator: \.isWhitespace).first.map(String.init)?.lowercased()
        guard let hex, hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        return hex
    }

    /// Mount the DMG and put it in front of the user. Replacing a running,
    /// signed app bundle from inside itself - while a tunnel may be up - buys
    /// one less drag at the cost of the riskiest code in the app, so we stop
    /// here.
    public func reveal(_ dmg: URL) throws {
        let attach = Process()
        attach.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        attach.arguments = ["attach", "-nobrowse", dmg.path]
        let pipe = Pipe()
        attach.standardOutput = pipe
        try attach.run()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        attach.waitUntilExit()

        // "…  /Volumes/Sweep VPN" - the mount point is the tail of the last line.
        let mount = out.split(whereSeparator: \.isNewline)
            .compactMap { line -> String? in
                guard let range = line.range(of: "/Volumes/") else { return nil }
                return String(line[range.lowerBound...]).trimmingCharacters(in: .whitespaces)
            }.last

        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = [mount ?? dmg.path]
        try open.run()
    }
}

extension Bundle {
    public var shortVersion: String {
        (object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0.0.0"
    }
}
#endif
