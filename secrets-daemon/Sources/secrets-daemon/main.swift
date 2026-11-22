import Foundation

// MARK: - Main

Logger.info("secrets-daemon starting...")

// Get socket path from environment or use default
let socketPath: String
if let envPath = ProcessInfo.processInfo.environment["SECRETS_SOCKET"] {
    socketPath = envPath
} else {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    socketPath = "\(home)/.secrets/daemon.sock"
}

// Ensure parent directory exists
let parentDir = (socketPath as NSString).deletingLastPathComponent
try? FileManager.default.createDirectory(atPath: parentDir, withIntermediateDirectories: true)

// Create server
let server = SocketServer(socketPath: socketPath)

// Setup signal handlers
var running = true

signal(SIGINT) { _ in
    Logger.info("Received SIGINT, shutting down...")
    running = false
}

signal(SIGTERM) { _ in
    Logger.info("Received SIGTERM, shutting down...")
    running = false
}

// Initialize components
let state = SessionStore()
let verifier = ClientVerifier.shared
let rateLimiter = RateLimiter.shared

server.requestHandler = { pid, request in
    if request.cmd == .ping { return .ping() }
    guard verifier.verify(pid: pid).isSuccess else {
        return .error(.unauthorized, message: "Client CDHash not in whitelist")
    }
    switch rateLimiter.checkLimit(for: pid) {
    case .allowed: break
    case .rateLimited, .blocked:
        return .error(.rateLimited, message: "Too many requests")
    }
    if request.cmd == .retireLegacyPin { return retireLegacyPin() }
    return state.handle(request)
}

// Start server
do {
    try server.start()

    Logger.info("secrets-daemon v\(ProtocolConstants.version) ready")

    // Run accept loop - it will exit when server.stop() is called
    DispatchQueue.global(qos: .userInitiated).async {
        server.acceptLoop()
    }

    // Wait for signal
    while running {
        Thread.sleep(forTimeInterval: 0.1)
    }

} catch ServerError.socketCreationFailed(let err) {
    Logger.error("Failed to create socket: \(err)")
    exit(1)
} catch ServerError.bindFailed(let err) {
    Logger.error("Failed to bind socket: \(err)")
    exit(1)
} catch ServerError.listenFailed(let err) {
    Logger.error("Failed to listen: \(err)")
    exit(1)
} catch {
    Logger.error("Unexpected error: \(error)")
    exit(1)
}

// Cleanup
server.stop()
Logger.info("secrets-daemon stopped")
