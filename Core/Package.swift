// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SweepVPNCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "SweepVPNCore", targets: ["SweepVPNCore"])],
    targets: [
        .target(name: "SweepVPNCore"),
        .testTarget(name: "SweepVPNCoreTests", dependencies: ["SweepVPNCore"]),
    ]
)
