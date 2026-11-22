import Foundation

enum ProtocolConstants {
    static let version = 2
    static let maxRequestSize = 8192
    static let maxResponseSize = 65536
    static let maxStringLength = 4096
}

/// Owns the long-lived key/session allocation. JSON/String copies are temporary;
/// this does not claim protection against a debugger or a compromised OS.
final class SecureBytes {
    private let memory: UnsafeMutableRawPointer
    private let count: Int
    init?(_ string: String) {
        let size = string.utf8.count
        let storage = UnsafeMutableRawPointer.allocate(byteCount: max(size, 1), alignment: 8)
        _ = string.withCString { memcpy(storage, $0, size) }
        guard mlock(storage, size) == 0 else {
            memset_s(storage, size, 0, size)
            storage.deallocate()
            return nil
        }
        count = size
        memory = storage
    }
    var string: String { String(decoding: UnsafeRawBufferPointer(start: memory, count: count), as: UTF8.self) }
    deinit {
        memset_s(memory, count, 0, count)
        munlock(memory, count)
        memory.deallocate()
    }
}

extension Data {
    mutating func secureZero() { guard !isEmpty else { return }; resetBytes(in: 0..<count) }
}

enum Command: String, Codable {
    case ping = "PING"
    case getState = "GET_STATE"
    case setState = "SET_STATE"
    case clearState = "CLEAR_STATE"
    case checkSession = "CHECK_SESSION"
    case retireLegacyPin = "RETIRE_LEGACY_PIN"
}
struct Request: Codable {
    let v: Int
    let cmd: Command
    let context: String?
    let masterKey: String?
    let providerSession: String?
    static func fromJSON(_ data: Data) -> Result<Request, ErrorCode> {
        guard data.count <= ProtocolConstants.maxRequestSize,
              let request = try? JSONDecoder().decode(Request.self, from: data),
              request.v == ProtocolConstants.version else { return .failure(.invalidRequest) }
        for field in [request.context, request.masterKey, request.providerSession] {
            if let field = field, field.utf8.count > ProtocolConstants.maxStringLength { return .failure(.invalidRequest) }
        }
        if request.cmd == .getState || request.cmd == .setState || request.cmd == .checkSession {
            guard let context = request.context, !context.isEmpty else { return .failure(.invalidRequest) }
        }
        if request.cmd == .setState {
            guard let key = request.masterKey, Data(base64Encoded: key)?.count == 32 else { return .failure(.invalidRequest) }
        }
        return .success(request)
    }
}
enum ResponseStatus: String, Codable { case ok, error, alive }
enum ErrorCode: String, Codable, Error {
    case unauthorized = "UNAUTHORIZED"
    case keychainError = "KEYCHAIN_ERROR"
    case invalidRequest = "INVALID_REQUEST"
    case rateLimited = "RATE_LIMITED"
    case sessionExpired = "SESSION_EXPIRED"
}
struct Response: Codable {
    var v: Int = ProtocolConstants.version
    var status: ResponseStatus
    var masterKey: String? = nil
    var providerSession: String? = nil
    var version: Int? = nil
    var code: ErrorCode? = nil
    var message: String? = nil
    var sessionActive: Bool? = nil
    static func ping() -> Response { Response(status: .alive, version: ProtocolConstants.version) }
    static func ok() -> Response { Response(status: .ok) }
    static func error(_ code: ErrorCode, message: String) -> Response { Response(status: .error, code: code, message: message) }
    func toJSON() -> Data? { try? JSONEncoder().encode(self) }
}
