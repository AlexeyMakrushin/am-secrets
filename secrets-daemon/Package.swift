// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "secrets-daemon",
    platforms: [.macOS(.v12)],
    targets: [
        .executableTarget(
            name: "secrets-daemon",
            path: "Sources/secrets-daemon"
        ),
        .testTarget(
            name: "secrets-daemonTests",
            dependencies: ["secrets-daemon"],
            path: "Tests/secrets-daemonTests"
        )
    ]
)
