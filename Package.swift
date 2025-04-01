// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoSuite",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
        .tvOS(.v16),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "CryptoSuite",
            targets: ["CryptoSuite"]),
    ],
    dependencies: [
        .package(url: "https://github.com/bpluta/Keyrmes.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "CryptoSuite",
            dependencies: [
                .product(name: "Keyrmes", package: "Keyrmes"),
            ]
        ),
        .testTarget(
            name: "CryptoSuiteTests",
            dependencies: ["CryptoSuite"]
        ),
    ]
)
