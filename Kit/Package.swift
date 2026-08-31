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
        .target(name: "SweepVPNKit", dependencies: [
            .product(name: "SweepVPNCore", package: "Core"), "SweepWireGuardC",
        ]),
        .target(name: "SweepVPNUI", dependencies: ["SweepVPNKit",
            .product(name: "SweepVPNCore", package: "Core")]),
        .testTarget(name: "SweepVPNKitTests", dependencies: ["SweepVPNKit", "SweepVPNUI"]),
    ]
)
