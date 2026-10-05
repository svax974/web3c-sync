// swift-tools-version:5.9
//
// Manifeste racine : SwiftPM n'accepte une dépendance distante que si
// Package.swift est à la racine du dépôt. Les sources restent dans
// clients/swift ; les vecteurs de test partagés vivent dans spec/vectors.
import PackageDescription

let package = Package(
    name: "Web3CSync",
    platforms: [.tvOS(.v16), .iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "Web3CSync", targets: ["Web3CSync"]),
    ],
    targets: [
        .target(name: "Web3CSync", path: "clients/swift/Sources/Web3CSync"),
        .testTarget(
            name: "Web3CSyncTests",
            dependencies: ["Web3CSync"],
            path: "clients/swift/Tests/Web3CSyncTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
