// Migration only: the daemon no longer reads or stores secrets in Keychain.
import Security

func retireLegacyPin() -> Response {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                               kSecAttrService as String: "ai-secrets",
                               kSecAttrAccount as String: "pin"]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound { return .ok() }
    return .error(.keychainError, message: "Legacy Keychain cleanup failed (status \(status))")
}
