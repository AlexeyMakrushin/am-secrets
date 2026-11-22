import Foundation

// MARK: - Logger

enum LogLevel: String {
    case debug = "DEBUG"
    case info = "INFO"
    case warning = "WARNING"
    case error = "ERROR"
}

enum Logger {
    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter
    }()

    private static var minLevel: LogLevel = .info

    static func setLevel(_ level: LogLevel) {
        minLevel = level
    }

    static func debug(_ message: String, file: String = #file, line: Int = #line) {
        log(.debug, message, file: file, line: line)
    }

    static func info(_ message: String, file: String = #file, line: Int = #line) {
        log(.info, message, file: file, line: line)
    }

    static func warning(_ message: String, file: String = #file, line: Int = #line) {
        log(.warning, message, file: file, line: line)
    }

    static func error(_ message: String, file: String = #file, line: Int = #line) {
        log(.error, message, file: file, line: line)
    }

    private static func log(_ level: LogLevel, _ message: String, file: String, line: Int) {
        guard shouldLog(level) else { return }

        let timestamp = dateFormatter.string(from: Date())
        let filename = (file as NSString).lastPathComponent
        let output = "[\(timestamp)] [\(level.rawValue)] [\(filename):\(line)] \(message)"

        // Thread-safe output
        if level == .error {
            FileHandle.standardError.write(Data((output + "\n").utf8))
        } else {
            print(output)
            fflush(stdout)
        }
    }

    private static func shouldLog(_ level: LogLevel) -> Bool {
        let levels: [LogLevel] = [.debug, .info, .warning, .error]
        guard let currentIndex = levels.firstIndex(of: minLevel),
              let messageIndex = levels.firstIndex(of: level) else {
            return false
        }
        return messageIndex >= currentIndex
    }
}
