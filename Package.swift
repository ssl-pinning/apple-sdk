// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "SslPinning",
    platforms: [
        .macOS(.v12),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8),
    ],
    products: [
        .library(
            name: "SslPinning",
            targets: ["SslPinning"]
        ),
    ],
    targets: [
        .target(
            name: "SslPinning"
        ),
        .testTarget(
            name: "SslPinningTests",
            dependencies: ["SslPinning"]
        ),
    ]
)
