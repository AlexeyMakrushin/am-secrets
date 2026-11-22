import Foundation

// MARK: - Rate Limiter

final class RateLimiter {
    static let shared = RateLimiter()

    private let maxRequestsPerMinute = 10
    private let maxRequestsPer5Min = 50
    private let blockDuration: TimeInterval = 600 // 10 minutes

    private var requestCounts: [pid_t: RequestHistory] = [:]
    private let lock = NSLock()

    private init() {}

    // MARK: - Check Rate Limit

    func checkLimit(for pid: pid_t) -> RateLimitResult {
        lock.lock()
        defer { lock.unlock() }

        let now = Date()

        // Get or create history for this PID
        var history = requestCounts[pid] ?? RequestHistory()

        // Clean up old entries
        history.cleanup(now: now)

        // Check if blocked
        if let blockedUntil = history.blockedUntil, blockedUntil > now {
            let remaining = Int(blockedUntil.timeIntervalSince(now))
            Logger.warning("PID \(pid) is blocked for \(remaining) more seconds")
            return .blocked(secondsRemaining: remaining)
        }

        // Check 5-minute limit
        let requests5min = history.requestsInLast(minutes: 5, from: now)
        if requests5min >= maxRequestsPer5Min {
            history.blockedUntil = now.addingTimeInterval(blockDuration)
            requestCounts[pid] = history
            Logger.warning("PID \(pid) exceeded 5-min limit (\(requests5min) requests), blocking for 10 minutes")
            return .blocked(secondsRemaining: Int(blockDuration))
        }

        // Check 1-minute limit
        let requests1min = history.requestsInLast(minutes: 1, from: now)
        if requests1min >= maxRequestsPerMinute {
            // Calculate backoff
            let backoffSeconds = history.calculateBackoff()
            Logger.warning("PID \(pid) exceeded 1-min limit (\(requests1min) requests), backoff: \(backoffSeconds)s")
            // Persist updated history so backoff escalates on repeated overlimit
            requestCounts[pid] = history
            return .rateLimited(backoffSeconds: backoffSeconds)
        }

        // Allow request
        history.recordRequest(at: now)
        requestCounts[pid] = history
        return .allowed
    }

    // MARK: - Reset (for testing)

    func reset() {
        lock.lock()
        requestCounts.removeAll()
        lock.unlock()
    }
}

// MARK: - Rate Limit Result

enum RateLimitResult {
    case allowed
    case rateLimited(backoffSeconds: Int)
    case blocked(secondsRemaining: Int)

    var isAllowed: Bool {
        if case .allowed = self { return true }
        return false
    }
}

// MARK: - Request History

private struct RequestHistory {
    var requests: [Date] = []
    var blockedUntil: Date?
    var consecutiveOverlimits = 0

    mutating func cleanup(now: Date) {
        // Remove requests older than 5 minutes
        let cutoff = now.addingTimeInterval(-300)
        requests.removeAll { $0 < cutoff }

        // Clear block if expired
        if let blocked = blockedUntil, blocked <= now {
            blockedUntil = nil
            consecutiveOverlimits = 0
        }
    }

    func requestsInLast(minutes: Int, from now: Date) -> Int {
        let cutoff = now.addingTimeInterval(TimeInterval(-minutes * 60))
        return requests.filter { $0 >= cutoff }.count
    }

    mutating func recordRequest(at time: Date) {
        requests.append(time)
        // Reset overlimit counter on successful request
        consecutiveOverlimits = 0
    }

    mutating func calculateBackoff() -> Int {
        consecutiveOverlimits += 1
        // Exponential backoff: 1, 2, 4, 8, 16 seconds
        let backoff = min(Int(pow(2.0, Double(consecutiveOverlimits - 1))), 16)
        return backoff
    }
}
