// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SweepVPNKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "SweepVPNKit", targets: ["SweepVPNKit"]),
                .library(name: "SweepVPNUI", targets: ["SweepVPNUI"])],
    dependencies: [.package(path: "../Core")],
    targets: [
        .binaryTarget(name: "SweepWireGuardC", path: "../DataPlane/SweepWireGuard.xcframework"),
        // macOS-only for now: the slice carries OpenSSL, lz4 and fmt statically,
        // and those still need cross-compiling for the iOS targets. The
        // condition keeps the iOS build working in the meantime rather than
        // failing on a missing slice.
        .binaryTarget(name: "SweepOpenVPNC", path: "../DataPlane/SweepOpenVPN.xcframework"),
        .target(name: "SweepVPNKit", dependencies: [
            .product(name: "SweepVPNCore", package: "Core"), "SweepWireGuardC",
            .target(name: "SweepOpenVPNC", condition: .when(platforms: [.macOS])),
        ],
        // OpenVPN 3 is C++; a Swift target linking a C++ static library has to
        // ask for the standard library itself.
        linkerSettings: [.linkedLibrary("c++", .when(platforms: [.macOS]))]),
        .target(name: "SweepVPNUI", dependencies: ["SweepVPNKit",
            .product(name: "SweepVPNCore", package: "Core")]),
        .testTarget(name: "SweepVPNKitTests", dependencies: ["SweepVPNKit", "SweepVPNUI"]),
    ]
)
