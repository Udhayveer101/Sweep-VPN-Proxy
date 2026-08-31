// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "sweep-catalog",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "../../Core")],
    targets: [.executableTarget(name: "sweep-catalog",
                                dependencies: [.product(name: "SweepVPNCore", package: "Core")])]
)
