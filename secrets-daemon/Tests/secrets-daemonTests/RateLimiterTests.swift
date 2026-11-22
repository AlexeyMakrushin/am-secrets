import XCTest
@testable import secrets_daemon

final class RateLimiterTests: XCTestCase {
    override func setUp() {
        super.setUp()
        RateLimiter.shared.reset()
    }

    func testAllowsInitialRequests() {
        let pid: pid_t = 1234
        let result = RateLimiter.shared.checkLimit(for: pid)
        XCTAssertTrue(result.isAllowed)
    }

    func testRateLimitsAfterTenRequests() {
        let pid: pid_t = 4242

        for _ in 0..<10 {
            let result = RateLimiter.shared.checkLimit(for: pid)
            XCTAssertTrue(result.isAllowed)
        }

        let result1 = RateLimiter.shared.checkLimit(for: pid)
        switch result1 {
        case .rateLimited(let backoff):
            XCTAssertEqual(backoff, 1)
        default:
            XCTFail("Expected rateLimited after 10 requests")
        }

        let result2 = RateLimiter.shared.checkLimit(for: pid)
        switch result2 {
        case .rateLimited(let backoff):
            XCTAssertEqual(backoff, 2)
        default:
            XCTFail("Expected rateLimited with increased backoff")
        }
    }

    func testResetClearsState() {
        let pid: pid_t = 777

        for _ in 0..<10 {
            _ = RateLimiter.shared.checkLimit(for: pid)
        }
        _ = RateLimiter.shared.checkLimit(for: pid)

        RateLimiter.shared.reset()
        let result = RateLimiter.shared.checkLimit(for: pid)
        XCTAssertTrue(result.isAllowed)
    }
}
