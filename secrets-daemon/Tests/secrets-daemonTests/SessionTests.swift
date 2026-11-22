import XCTest
@testable import secrets_daemon

final class SessionTests: XCTestCase {
    func request(_ json: String) throws -> Request { try JSONDecoder().decode(Request.self, from: Data(json.utf8)) }
    func testSessionLivesUntilLockAndIsBoundToVault() throws {
        let store = SessionStore()
        let get = try request(#"{"v":2,"cmd":"GET_STATE","context":"vault-a"}"#)
        XCTAssertEqual(store.handle(get).code, .sessionExpired)
        let set = try request(#"{"v":2,"cmd":"SET_STATE","context":"vault-a","masterKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","providerSession":"test-session"}"#)
        XCTAssertEqual(store.handle(set).status, .ok)
        XCTAssertEqual(store.handle(get).providerSession, "test-session")
        XCTAssertEqual(store.handle(try request(#"{"v":2,"cmd":"GET_STATE","context":"vault-b"}"#)).code, .sessionExpired)
        XCTAssertEqual(SessionStore().handle(get).code, .sessionExpired)
        XCTAssertEqual(store.handle(try request(#"{"v":2,"cmd":"CLEAR_STATE"}"#)).status, .ok)
        XCTAssertEqual(store.handle(get).code, .sessionExpired)
    }
}
