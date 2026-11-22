import Foundation

// MARK: - Socket Server

final class SocketServer {
    private let socketPath: String
    private var serverSocket: Int32 = -1
    private var isRunning = false
    private let maxConnections = 10
    private let acceptTimeout: TimeInterval = 5.0
    private let readWriteTimeout: TimeInterval = 10.0

    private var activeConnections = 0
    private let connectionLock = NSLock()

    var requestHandler: ((Int32, Request) -> Response)?

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    deinit {
        stop()
    }

    // MARK: - Server Lifecycle

    func start() throws {
        // Remove existing socket file
        unlink(socketPath)

        // Create socket
        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            throw ServerError.socketCreationFailed(errno)
        }

        // Set socket options
        var reuseAddr: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, socklen_t(MemoryLayout<Int32>.size))

        // SECURITY: Set restrictive umask BEFORE bind to prevent race condition
        // This ensures socket is created with 600 permissions atomically
        let oldMask = umask(0o077)
        defer { umask(oldMask) } // Restore original umask after this scope

        // Bind to path
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        let pathLen = min(pathBytes.count, MemoryLayout.size(ofValue: addr.sun_path))
        withUnsafeMutableBytes(of: &addr.sun_path) { rawPtr in
            for i in 0..<(pathLen - 1) {
                rawPtr[i] = UInt8(bitPattern: pathBytes[i])
            }
            rawPtr[pathLen - 1] = 0
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(serverSocket, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard bindResult == 0 else {
            close(serverSocket)
            throw ServerError.bindFailed(errno)
        }

        // Explicitly set permissions to 600 (redundant but safe)
        chmod(socketPath, 0o600)

        // Listen
        guard listen(serverSocket, Int32(maxConnections)) == 0 else {
            close(serverSocket)
            throw ServerError.listenFailed(errno)
        }

        isRunning = true
        Logger.info("Server listening on \(socketPath)")
    }

    func stop() {
        isRunning = false
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
        unlink(socketPath)
        Logger.info("Server stopped")
    }

    // MARK: - Accept Loop

    func acceptLoop() {
        while isRunning {
            // Check connection limit
            connectionLock.lock()
            let canAccept = activeConnections < maxConnections
            connectionLock.unlock()

            guard canAccept else {
                usleep(10000) // 10ms
                continue
            }

            // Set accept timeout using poll
            var pollFd = pollfd(fd: serverSocket, events: Int16(POLLIN), revents: 0)
            let pollResult = poll(&pollFd, 1, Int32(acceptTimeout * 1000))

            if pollResult <= 0 {
                continue // Timeout or error
            }

            // Accept connection
            var clientAddr = sockaddr_un()
            var clientAddrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    accept(serverSocket, sockaddrPtr, &clientAddrLen)
                }
            }

            guard clientSocket >= 0 else {
                if errno != EAGAIN && errno != EWOULDBLOCK {
                    Logger.error("Accept failed: \(errno)")
                }
                continue
            }

            // Handle in background
            connectionLock.lock()
            activeConnections += 1
            connectionLock.unlock()

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.handleClient(socket: clientSocket)
                self?.connectionLock.lock()
                self?.activeConnections -= 1
                self?.connectionLock.unlock()
            }
        }
    }

    // MARK: - Client Handling

    private func handleClient(socket clientSocket: Int32) {
        defer { close(clientSocket) }

        // Set read/write timeout
        var timeout = timeval(tv_sec: Int(readWriteTimeout), tv_usec: 0)
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var noSigPipe: Int32 = 1
        setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        // Get client PID
        let clientPID = getClientPID(socket: clientSocket)
        Logger.debug("Connection from PID: \(clientPID)")

        // Read request with length-prefix framing
        guard let data = readFramedMessage(from: clientSocket) else {
            // Try legacy plain JSON read for backward compatibility
            if let legacyData = readLegacyMessage(from: clientSocket) {
                Logger.debug("Using legacy protocol for PID \(clientPID)")
                handleAndRespond(data: legacyData, clientPID: clientPID, socket: clientSocket, useLegacy: true)
            }
            return
        }

        handleAndRespond(data: data, clientPID: clientPID, socket: clientSocket, useLegacy: false)
    }

    private func handleAndRespond(data: Data, clientPID: pid_t, socket: Int32, useLegacy: Bool) {
        // Parse request
        var input = data
        defer { input.secureZero() }
        let response: Response
        switch Request.fromJSON(input) {
        case .success(let request):
            response = handleRequest(request, fromPID: clientPID, socket: socket)
        case .failure(let errorCode):
            response = Response.error(errorCode, message: "Invalid request format")
            Logger.warning("Invalid request from PID \(clientPID)")
        }

        if useLegacy {
            sendLegacyResponse(response, to: socket)
        } else {
            sendFramedResponse(response, to: socket)
        }
    }

    private func handleRequest(_ request: Request, fromPID pid: pid_t, socket: Int32) -> Response {
        guard let handler = requestHandler else {
            return Response.error(.invalidRequest, message: "No handler configured")
        }
        return handler(pid, request)
    }

    // MARK: - Length-Prefixed Protocol (v2)
    // Format: [4 bytes: big-endian uint32 length][JSON payload]

    private func readFramedMessage(from socket: Int32) -> Data? {
        // Read 4-byte length header
        var lengthBytes = [UInt8](repeating: 0, count: 4)
        let headerRead = recv(socket, &lengthBytes, 4, MSG_PEEK | MSG_WAITALL)

        guard headerRead >= 4 else {
            return nil // Not enough data for header, might be legacy
        }

        // Check if this looks like a length-prefix (first byte should be 0 for reasonable sizes)
        // JSON always starts with '{' (0x7B), so if first byte is 0x00, it's framed protocol
        guard lengthBytes[0] == 0 else {
            return nil // Likely legacy plain JSON
        }

        // Actually read the header
        _ = recv(socket, &lengthBytes, 4, 0)

        // Parse big-endian uint32 length
        let length = UInt32(lengthBytes[0]) << 24 |
                     UInt32(lengthBytes[1]) << 16 |
                     UInt32(lengthBytes[2]) << 8 |
                     UInt32(lengthBytes[3])

        guard length > 0, length <= UInt32(ProtocolConstants.maxRequestSize) else {
            Logger.warning("Invalid message length: \(length)")
            return nil
        }

        // Read the JSON payload
        var buffer = [UInt8](repeating: 0, count: Int(length))
        defer { buffer.withUnsafeMutableBytes { ptr in if let base = ptr.baseAddress { memset_s(base, ptr.count, 0, ptr.count) } } }
        var totalRead = 0

        while totalRead < Int(length) {
            let remaining = Int(length) - totalRead
            let bytesRead = buffer.withUnsafeMutableBytes { ptr in
                recv(socket, ptr.baseAddress!.advanced(by: totalRead), remaining, 0)
            }
            if bytesRead <= 0 {
                Logger.error("Failed to read message body")
                return nil
            }
            totalRead += bytesRead
        }

        return Data(buffer)
    }

    private func sendFramedResponse(_ response: Response, to socket: Int32) {
        guard var jsonData = response.toJSON() else {
            Logger.error("Failed to encode response")
            return
        }
        defer { jsonData.secureZero() } // SECURITY: Zeroize PIN data after sending

        guard jsonData.count <= ProtocolConstants.maxResponseSize else {
            Logger.error("Response too large: \(jsonData.count) bytes")
            return
        }

        // Build framed message: 4-byte length + JSON
        let length = UInt32(jsonData.count)
        var frame = Data(capacity: 4 + jsonData.count)

        // Big-endian length header
        frame.append(UInt8((length >> 24) & 0xFF))
        frame.append(UInt8((length >> 16) & 0xFF))
        frame.append(UInt8((length >> 8) & 0xFF))
        frame.append(UInt8(length & 0xFF))
        frame.append(jsonData)

        frame.withUnsafeBytes { ptr in
            var sent = 0
            while sent < frame.count {
                let n = send(socket, ptr.baseAddress!.advanced(by: sent), frame.count - sent, 0)
                if n <= 0 { break }
                sent += n
            }
        }

        // SECURITY: Zeroize frame buffer after sending
        frame.secureZero()
    }

    // MARK: - Legacy Protocol (v1 compatibility)

    private func readLegacyMessage(from socket: Int32) -> Data? {
        var buffer = [UInt8](repeating: 0, count: ProtocolConstants.maxRequestSize + 1)
        let bytesRead = recv(socket, &buffer, ProtocolConstants.maxRequestSize + 1, 0)

        guard bytesRead > 0, bytesRead <= ProtocolConstants.maxRequestSize else {
            return nil
        }

        return Data(buffer.prefix(bytesRead))
    }

    private func sendLegacyResponse(_ response: Response, to socket: Int32) {
        guard var data = response.toJSON() else {
            Logger.error("Failed to encode response")
            return
        }
        defer { data.secureZero() } // SECURITY: Zeroize PIN data after sending

        guard data.count <= ProtocolConstants.maxResponseSize else {
            Logger.error("Response too large: \(data.count) bytes")
            return
        }

        data.withUnsafeBytes { ptr in
            _ = send(socket, ptr.baseAddress, data.count, 0)
        }
    }

    // MARK: - Client PID

    private func getClientPID(socket: Int32) -> pid_t {
        var pid: pid_t = 0
        var pidLen = socklen_t(MemoryLayout<pid_t>.size)

        // macOS uses LOCAL_PEERPID
        let result = getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLen)
        if result == 0 {
            return pid
        }

        return -1
    }
}

// MARK: - Server Errors

enum ServerError: Error {
    case socketCreationFailed(Int32)
    case bindFailed(Int32)
    case listenFailed(Int32)
}
