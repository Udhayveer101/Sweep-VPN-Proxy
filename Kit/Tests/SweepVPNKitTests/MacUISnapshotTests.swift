#if os(macOS)
import XCTest
import SwiftUI
import SweepVPNCore
@testable import SweepVPNKit
@testable import SweepVPNUI

/// Renders the macOS surfaces off-screen so the layout can be inspected without
/// a signed build or screen-recording permission, and so an empty or clipped
/// view fails the suite instead of shipping.
@MainActor
final class MacUISnapshotTests: XCTestCase {
    static let outputDirectory = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("sweep-ui-snapshots", isDirectory: true)

    func makeModel(state: TunnelState, servers: [Server]) -> VPNViewModel {
        let model = VPNViewModel(configurator: VPNConfigurator(bundleIdentifier: "com.sweep.vpn.mac.tunnel"))
        model.load(servers: servers)
        model.apply(ranked: servers.enumerated().map { index, server in
            RankedServer(server: server, rttMs: Double(12 + index * 34), lossFraction: 0)
        })
        model.completeOnboarding()
        return model
    }

    func servers() -> [Server] {
        [("home-1", "My VPS — Frankfurt", "DE"), ("home-2", "Warm spare — Amsterdam", "NL"),
         ("se-sto", "Stockholm, Sweden", "SE")].map { id, name, code in
            Server(id: id, name: name, countryCode: code, publicKey: "pk",
                   endpoints: ProtocolRung.allCases.map {
                       .init(host: "198.51.100.10", port: 51820, rung: $0)
                   },
                   dnsServers: ["10.64.0.1"], ipv4Address: "10.64.0.2",
                   provider: "self-hosted", cityName: name)
        }
    }

    /// Fraction of sampled pixels that carry ink (text, glyphs, chrome). A view
    /// that failed to lay out renders as flat background and scores ~0.
    func inkFraction(of image: NSImage) throws -> Double {
        guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff) else {
            throw XCTSkip("no bitmap")
        }
        var ink = 0, total = 0
        let stepX = max(1, bitmap.pixelsWide / 200), stepY = max(1, bitmap.pixelsHigh / 200)
        for x in stride(from: 0, to: bitmap.pixelsWide, by: stepX) {
            for y in stride(from: 0, to: bitmap.pixelsHigh, by: stepY) {
                guard let c = bitmap.colorAt(x: x, y: y) else { continue }
                total += 1
                let luminance = 0.2126 * c.redComponent + 0.7152 * c.greenComponent
                    + 0.0722 * c.blueComponent
                if luminance < 0.5 { ink += 1 }
            }
        }
        return total == 0 ? 0 : Double(ink) / Double(total)
    }

    /// Bytes of a render, for comparing two states of the same view.
    func pixels(of image: NSImage) throws -> Data {
        guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]) else {
            throw XCTSkip("no bitmap")
        }
        return png
    }

    @discardableResult
    func render(_ view: some View, size: CGSize, name: String) throws -> NSImage {
        let renderer = ImageRenderer(content: view.frame(width: size.width, height: size.height))
        renderer.scale = 2
        guard let image = renderer.nsImage else {
            XCTFail("\(name) produced no image"); throw XCTSkip("no renderer output")
        }
        XCTAssertGreaterThan(image.size.width, 100, "\(name) rendered too narrow")
        XCTAssertGreaterThan(image.size.height, 100, "\(name) rendered too short")
        XCTAssertGreaterThan(try inkFraction(of: image), 0.001,
                             "\(name) has no drawn content at all")

        try FileManager.default.createDirectory(at: Self.outputDirectory,
                                                withIntermediateDirectories: true)
        if let tiff = image.tiffRepresentation,
           let bitmap = NSBitmapImageRep(data: tiff),
           let png = bitmap.representation(using: .png, properties: [:]) {
            try png.write(to: Self.outputDirectory.appendingPathComponent("\(name).png"))
        }
        return image
    }

    func testMenuBarHomeRendersInEveryImportantState() throws {
        let states: [(String, TunnelState, ProtocolRung?, Presentation.Quality?)] = [
            ("home-disconnected", .disconnected, nil, nil),
            ("home-connected", .connected(rung: .wireGuardUDP, server: "home-1"), .wireGuardUDP, .good),
            ("home-stealth", .connected(rung: .wireGuardTLS, server: "home-1"), .wireGuardTLS, .fair),
            ("home-degraded", .degraded(rung: .wireGuardQUIC, reason: .highLoss), .wireGuardQUIC, .weak),
            ("home-reconnecting", .reconnecting(attempt: 1), .wireGuardTLS, nil),
            ("home-blocked", .killSwitchActive, nil, nil),
        ]
        for (name, state, rung, quality) in states {
            let model = makeModel(state: state, servers: servers())
            model.overrideStateForPreview(state, rung: rung, quality: quality)
            if case .connected = state {
                XCTAssertEqual(model.routeDescription == nil, rung == .wireGuardUDP,
                               "a fallback route must be named on screen")
            }
            try render(HomeView(model: model), size: CGSize(width: 380, height: 460), name: name)
        }
    }

    func testServerPickerRendersOrderedList() throws {
        let model = makeModel(state: .disconnected, servers: servers())
        // Render the row content directly: an off-screen pass does not lay out
        // a ScrollView's children, so snapshotting the container proves nothing.
        try render(ServerPickerView(model: model).content,
                   size: CGSize(width: 420, height: 560), name: "server-picker")
        // The renderer returns an identical placeholder for a view it cannot lay
        // out, so prove the pixels actually follow the data.
        let single = makeModel(state: TunnelState.disconnected, servers: [servers()[0]])
        let one = try render(ServerPickerView(model: single).content,
                             size: CGSize(width: 420, height: 560), name: "server-picker-single")
        let many = try render(ServerPickerView(model: model).content,
                              size: CGSize(width: 420, height: 560), name: "server-picker")
        XCTAssertNotEqual(try pixels(of: one), try pixels(of: many),
                          "the list render does not depend on the server list")

        // Row order is the product requirement: Automatic, fastest, then the rest.
        guard case .automatic = model.listEntries.first else { return XCTFail("row 1 must be Automatic") }
        guard case .fastest(let pinned, _) = model.listEntries[1] else {
            return XCTFail("row 2 must be the fastest server")
        }
        XCTAssertEqual(pinned.id, "home-1")
    }

    /// Settings uses `.formStyle(.grouped)`, which does not lay out in an
    /// off-screen render pass, so this is NOT a visual check — it only proves the
    /// view and its macOS-only section construct and expose the right extension
    /// identifiers. The macOS Settings layout itself is unverified here; it needs
    /// a look at the running app.
    func testSettingsConstructsWithTheMacSection() throws {
        let model = makeModel(state: .disconnected, servers: servers())
        XCTAssertEqual(model.tunnelExtensionID, "com.sweep.vpn.mac.tunnel")
        XCTAssertEqual(model.filterExtensionID, "com.sweep.vpn.mac.filter")
        _ = SettingsView(model: model).body
        _ = MacSettingsSection(model: model, tunnelExtensionID: model.tunnelExtensionID,
                               filterExtensionID: model.filterExtensionID).body
    }

    func testOnboardingRenders() throws {
        let model = makeModel(state: .disconnected, servers: servers())
        try render(OnboardingView(model: model), size: CGSize(width: 460, height: 640), name: "onboarding")
    }
}
#endif
