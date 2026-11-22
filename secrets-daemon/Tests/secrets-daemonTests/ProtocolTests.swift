import XCTest
@testable import secrets_daemon

final class ProtocolTests: XCTestCase {
    func testValidPing() {
        if case .success(let req) = Request.fromJSON(Data(#"{"v":2,"cmd":"PING"}"#.utf8)) {
            XCTAssertEqual(req.cmd, .ping)
        } else { XCTFail("Valid ping rejected") }
    }
    func testLegacyAndInvalidRequestsRejected() {
        for json in [#"{"v":1,"cmd":"GET_PIN"}"#,
                     #"{"v":2,"cmd":"SET_STATE","context":"x"}"#,
                     #"{"v":2,"cmd":"SET_STATE","context":"x","masterKey":"bad"}"#,
                     #"{"v":2,"cmd":"GET_STATE"}"#] {
            if case .success = Request.fromJSON(Data(json.utf8)) { XCTFail("Invalid request accepted") }
        }
    }
    func testOversizedRequestRejected() {
        if case .success = Request.fromJSON(Data(repeating: 0x7B, count: ProtocolConstants.maxRequestSize + 1)) { XCTFail("Oversized request accepted") }
    }
    func testStatusContainsNoKey() throws {
        let response = Response(status: .ok, sessionActive: false)
        let data = try XCTUnwrap(response.toJSON())
        let decoded = try JSONDecoder().decode(Response.self, from: data)
        XCTAssertNil(decoded.masterKey)
        XCTAssertNil(decoded.providerSession)
    }
}
