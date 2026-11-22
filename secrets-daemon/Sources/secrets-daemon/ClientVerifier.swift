import Foundation
import Security

// MARK: - Client Verifier

final class ClientVerifier {
    static let shared = ClientVerifier()

    private let trustedHashesPath: String
    private var trustedHashes: Set<String> = []
    private var lastLoadTime: Date?
    private let reloadInterval: TimeInterval = 5.0 // Reload whitelist every 5 seconds

    // Guards trustedHashes and lastLoadTime: clients are served on a concurrent
    // queue, so reads and the periodic reload run on different threads at once.
    private let hashLock = NSLock()

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let directory = ProcessInfo.processInfo.environment["SECRETS_HOME"] ?? "\(home)/.secrets"
        trustedHashesPath = "\(directory)/trusted_hashes"
        hashLock.lock()
        loadTrustedHashesLocked()
        hashLock.unlock()
    }

    // MARK: - Verification

    func verify(pid: pid_t) -> VerificationResult {
        // SECURITY: Use SecCodeCopyGuestWithAttributes to verify the running process directly
        // This prevents TOCTOU attacks where binary is replaced between path lookup and verification
        guard let cdhash = getCDHashByPID(pid: pid) else {
            // Fallback to path-based verification with warning
            Logger.warning("Direct PID verification failed for \(pid), trying path-based fallback")

            guard let path = getProcessPath(pid: pid) else {
                Logger.warning("Could not get path for PID \(pid)")
                return .failure("Could not determine client path")
            }

            guard let fallbackHash = getCDHash(path: path) else {
                Logger.warning("Could not compute CDHash for \(path)")
                return .failure("Could not verify client signature")
            }

            Logger.debug("Client CDHash (path-based): \(fallbackHash)")

            if isTrusted(fallbackHash) {
                Logger.debug("Client verified (path-based): \(fallbackHash)")
                return .success
            }

            Logger.warning("Client CDHash not in whitelist: \(fallbackHash)")
            return .failure("Client CDHash not in whitelist")
        }

        Logger.debug("Client CDHash (PID-based): \(cdhash)")

        // Check if CDHash is in whitelist (reloads it when stale)
        if isTrusted(cdhash) {
            Logger.debug("Client verified: \(cdhash)")
            return .success
        }

        Logger.warning("Client CDHash not in whitelist: \(cdhash)")
        return .failure("Client CDHash not in whitelist")
    }

    // MARK: - PID-based CDHash (TOCTOU-safe)

    private func getCDHashByPID(pid: pid_t) -> String? {
        // Use SecCodeCopyGuestWithAttributes to get code reference directly from PID
        // This verifies the running process, not the file on disk
        var guestCode: SecCode?

        let attributes = [kSecGuestAttributePid: pid] as CFDictionary

        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &guestCode)
        guard status == errSecSuccess, let code = guestCode else {
            Logger.debug("SecCodeCopyGuestWithAttributes failed for PID \(pid): \(status)")
            return nil
        }

        // Convert SecCode to SecStaticCode for signing information
        var staticCode: SecStaticCode?
        let copyStatus = SecCodeCopyStaticCode(code, [], &staticCode)
        guard copyStatus == errSecSuccess, let sCode = staticCode else {
            Logger.debug("SecCodeCopyStaticCode failed for PID \(pid): \(copyStatus)")
            return nil
        }

        // Get signing information from the running process
        var signingInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(sCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)
        guard infoStatus == errSecSuccess, let info = signingInfo as? [String: Any] else {
            Logger.debug("Failed to get signing info for PID \(pid): \(infoStatus)")
            return nil
        }

        // Extract CDHash from running process
        if let cdhashes = info[kSecCodeInfoCdHashes as String] as? [Data], let first = cdhashes.first {
            return first.map { String(format: "%02x", $0) }.joined()
        }

        if let uniqueID = info[kSecCodeInfoUnique as String] as? Data {
            return uniqueID.map { String(format: "%02x", $0) }.joined()
        }

        Logger.debug("No CDHash found for PID \(pid)")
        return nil
    }

    // MARK: - Process Path

    private func getProcessPath(pid: pid_t) -> String? {
        // Use proc_pidpath to get the path of the process
        var pathBuffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))

        let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard pathLength > 0 else {
            return nil
        }

        return String(cString: pathBuffer)
    }

    // MARK: - CDHash Extraction

    private func getCDHash(path: String) -> String? {
        // Create a static code reference for the binary
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path)

        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            Logger.debug("Failed to create static code for \(path): \(createStatus)")
            return nil
        }

        // Get signing information
        var signingInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)
        guard infoStatus == errSecSuccess, let info = signingInfo as? [String: Any] else {
            Logger.debug("Failed to get signing info for \(path): \(infoStatus)")
            return nil
        }

        // Extract CDHash
        // The CDHash is stored in the cdhashes array
        if let cdhashes = info[kSecCodeInfoCdHashes as String] as? [Data], let first = cdhashes.first {
            return first.map { String(format: "%02x", $0) }.joined()
        }

        // Try unique identifier as fallback
        if let uniqueID = info[kSecCodeInfoUnique as String] as? Data {
            return uniqueID.map { String(format: "%02x", $0) }.joined()
        }

        Logger.debug("No CDHash found in signing info for \(path)")
        return nil
    }

    // MARK: - Whitelist Management

    /// Checks a hash against the whitelist, reloading it first if stale.
    /// The whole read-reload-compare sequence happens under one lock.
    private func isTrusted(_ hash: String) -> Bool {
        hashLock.lock()
        defer { hashLock.unlock() }

        reloadTrustedHashesIfNeededLocked()
        return trustedHashes.contains(hash)
    }

    /// Caller must hold hashLock.
    private func loadTrustedHashesLocked() {
        trustedHashes.removeAll()

        guard FileManager.default.fileExists(atPath: trustedHashesPath) else {
            Logger.warning("Trusted hashes file not found: \(trustedHashesPath)")
            return
        }

        do {
            let content = try String(contentsOfFile: trustedHashesPath, encoding: .utf8)
            for line in content.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)

                // Skip empty lines and comments
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else {
                    continue
                }

                // Extract hash (first word)
                let parts = trimmed.components(separatedBy: .whitespaces)
                if let hash = parts.first, !hash.isEmpty {
                    trustedHashes.insert(hash.lowercased())
                }
            }

            lastLoadTime = Date()
            Logger.info("Loaded \(trustedHashes.count) trusted hashes")
        } catch {
            Logger.error("Failed to load trusted hashes: \(error)")
        }
    }

    /// Caller must hold hashLock.
    private func reloadTrustedHashesIfNeededLocked() {
        if let lastLoad = lastLoadTime {
            let elapsed = Date().timeIntervalSince(lastLoad)
            if elapsed < reloadInterval {
                return
            }
        }
        loadTrustedHashesLocked()
    }

    // MARK: - Add Hash (for setup/trust commands)

    func addHash(_ hash: String, comment: String) -> Bool {
        hashLock.lock()
        defer { hashLock.unlock() }

        // Ensure directory exists
        let dir = (trustedHashesPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        // Read existing content
        var content = ""
        if FileManager.default.fileExists(atPath: trustedHashesPath) {
            content = (try? String(contentsOfFile: trustedHashesPath, encoding: .utf8)) ?? ""
        } else {
            content = "# Trusted CDHashes for ai-secrets\n# Format: cdhash comment\n"
        }

        // Check if hash already exists
        if trustedHashes.contains(hash.lowercased()) {
            Logger.info("Hash already in whitelist: \(hash)")
            return true
        }

        // Append new hash
        let entry = "\(hash) \(comment)\n"
        content += entry

        do {
            try content.write(toFile: trustedHashesPath, atomically: true, encoding: .utf8)
            // Set permissions to 600
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: trustedHashesPath)
            trustedHashes.insert(hash.lowercased())
            Logger.info("Added hash to whitelist: \(hash)")
            return true
        } catch {
            Logger.error("Failed to write trusted hashes: \(error)")
            return false
        }
    }
}

// MARK: - Verification Result

enum VerificationResult {
    case success
    case failure(String)

    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}

// MARK: - proc_pidpath declaration

// This is from libproc.h
@_silgen_name("proc_pidpath")
func proc_pidpath(_ pid: pid_t, _ buffer: UnsafeMutableRawPointer, _ buffersize: UInt32) -> Int32

let PROC_PIDPATHINFO_MAXSIZE: Int32 = 4096
