import Foundation

/// Accessed only after client verification. One machine-local vault at a time.
final class SessionStore {
    private let lock = NSLock()
    private var context: String?
    private var masterKey: SecureBytes?
    private var providerSession: SecureBytes?

    func handle(_ request: Request) -> Response {
        lock.lock()
        defer { lock.unlock() }
        switch request.cmd {
        case .setState:
            guard let key = request.masterKey, Data(base64Encoded: key)?.count == 32,
                  let newContext = request.context, !newContext.isEmpty else {
                return .error(.invalidRequest, message: "Valid key and context required")
            }
            guard let storedKey = SecureBytes(key) else {
                return .error(.invalidRequest, message: "Unable to lock key memory")
            }
            let storedSession = request.providerSession.flatMap { $0.isEmpty ? nil : SecureBytes($0) }
            if let value = request.providerSession, !value.isEmpty, storedSession == nil {
                return .error(.invalidRequest, message: "Unable to lock session memory")
            }
            masterKey = storedKey
            providerSession = storedSession
            context = newContext
            return .ok()
        case .getState:
            guard request.context == context, let key = masterKey else {
                return .error(.sessionExpired, message: "Vault locked. Run secrets unlock in your terminal.")
            }
            return Response(status: .ok, masterKey: key.string, providerSession: providerSession?.string)
        case .checkSession:
            return Response(status: .ok, sessionActive: masterKey != nil && request.context == context)
        case .clearState:
            masterKey = nil
            providerSession = nil
            context = nil
            return .ok()
        default:
            return .error(.invalidRequest, message: "Unsupported state command")
        }
    }
}
