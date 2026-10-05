// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Web3CSync",
    platforms: [.tvOS(.v16), .iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "Web3CSync", targets: ["Web3CSync"]),
    ],
    targets: [
        .target(name: "Web3CSync"),
        .testTarget(name: "Web3CSyncTests", dependencies: ["Web3CSync"]),
    ],
    swiftLanguageVersions: [.v5]
)
