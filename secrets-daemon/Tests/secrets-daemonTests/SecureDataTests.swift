import XCTest
@testable import secrets_daemon

final class SecureDataTests: XCTestCase {
    func testDataSecureZero() {
        var data = Data([1, 2, 3, 4])
        data.secureZero()
        XCTAssertTrue(data.allSatisfy { $0 == 0 })
    }
}
