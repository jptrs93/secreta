import CryptoKit
import Foundation
import LocalAuthentication
import Security

final class SecretService {
    private let keychain: KeychainAdapter
    private let cache: CacheManager
    private let policy: PolicyEngine
    private let auditLogger: AuditLogger
    private let notificationBridge: NotificationCenterBridge
    private let auth: AuthChallenge
    private let startDate = Date()

    init(keychain: KeychainAdapter,
         cache: CacheManager,
         policy: PolicyEngine,
         auditLogger: AuditLogger,
         notificationBridge: NotificationCenterBridge,
         auth: AuthChallenge) {
        self.keychain = keychain
        self.cache = cache
        self.policy = policy
        self.auditLogger = auditLogger
        self.notificationBridge = notificationBridge
        self.auth = auth
    }

    func createSecret(request: SecretCreateRequest) -> SecretCreateResponse {
        let cacheSeconds = max(request.cacheSeconds ?? 0, 0)
        let storedName = storedName(for: request.name)
        let secretId = UUID().uuidString
        let metadata = StoredSecretMetadata(cacheSeconds: cacheSeconds, createdAt: Date(), lastAccessAt: nil)
        keychain.storeSecret(name: storedName, secret: request.secretValue, metadata: metadata)
        policy.recordSecret(name: request.name, metadata: metadata)

        let identity = policy.resolveClientIdentity()
        let event = AuditEvent(
            requestId: UUID(),
            timestamp: Date(),
            client: identity,
            action: "secret.create",
            secretName: request.name,
            result: "success",
            metadata: ["cache_seconds": String(cacheSeconds)]
        )
        auditLogger.log(event)
        notificationBridge.postSecretAccess(event: event)

        return SecretCreateResponse(secretId: secretId, storedName: storedName, cacheSeconds: cacheSeconds)
    }

    private func storedName(for name: String) -> String {
        if name.hasPrefix("sa:") {
            return name
        }
        return "sm:\(name)"
    }

    private func loadMetadata(for name: String) -> StoredSecretMetadata? {
        if let existing = policy.metadata(for: name) {
            return existing
        }
        guard let metadata = keychain.readMetadata(name: storedName(for: name)) else {
            return nil
        }
        policy.recordSecret(name: name, metadata: metadata)
        return metadata
    }

    func accessSecret(request: SecretAccessRequest) -> Result<SecretAccessResponse, ServiceError> {
        guard let metadata = loadMetadata(for: request.name) else {
            return .failure(ServiceError(code: "not_found", message: "Unknown secret"))
        }
        let identity = policy.resolveClientIdentity()
        let requiresAuth = !cache.hasValidCache(for: identity.cdhash, secretName: request.name)
        var authSatisfied = false
        if requiresAuth {
            let prompt = authPrompt(identity: identity, request: request)
            authSatisfied = auth.evaluate(prompt: prompt)
            if !authSatisfied {
                recordAccess(identity: identity, secretName: request.name, result: "auth_failed", metadata: metadata)
                return .failure(ServiceError(code: "auth_failed", message: "Authentication failed"))
            }
            cache.storeCache(for: identity.cdhash, secretName: request.name, cacheSeconds: metadata.cacheSeconds)
        }
        let storedName = storedName(for: request.name)
        guard let secret = keychain.readSecret(name: storedName) else {
            recordAccess(identity: identity, secretName: request.name, result: "not_found", metadata: metadata)
            return .failure(ServiceError(code: "not_found", message: "Secret missing in keychain"))
        }
        policy.recordAccess(name: request.name)
        let response = SecretAccessResponse(secretValue: secret, cacheSeconds: metadata.cacheSeconds, authRequired: requiresAuth, authSatisfied: authSatisfied || !requiresAuth)
        recordAccess(identity: identity, secretName: request.name, result: "success", metadata: metadata)
        return .success(response)
    }

    func secretMeta(name: String) -> Result<SecretMetaResponse, ServiceError> {
        guard let metadata = loadMetadata(for: name) else {
            return .failure(ServiceError(code: "not_found", message: "Unknown secret"))
        }
        let response = SecretMetaResponse(cacheSeconds: metadata.cacheSeconds, lastAccessAt: metadata.lastAccessAt, createdAt: metadata.createdAt)
        return .success(response)
    }

    func deleteSecret(name: String) -> Result<SecretDeleteResponse, ServiceError> {
        let metadata = loadMetadata(for: name)
        let deleted = keychain.deleteSecret(name: storedName(for: name))
        if !deleted {
            return .failure(ServiceError(code: "not_found", message: "Unknown secret"))
        }
        policy.removeSecret(name: name)
        cache.removeCache(for: name)

        let identity = policy.resolveClientIdentity()
        let event = AuditEvent(
            requestId: UUID(),
            timestamp: Date(),
            client: identity,
            action: "secret.delete",
            secretName: name,
            result: "success",
            metadata: metadata.map { ["cache_seconds": String($0.cacheSeconds)] }
        )
        auditLogger.log(event)
        notificationBridge.postSecretAccess(event: event)

        return .success(SecretDeleteResponse(deleted: true))
    }

    func readFile(request: FileReadRequest) -> Result<FileReadResponse, ServiceError> {
        let fileUrl = FilePathResolver.resolve(request.path)
        let identity = policy.resolveClientIdentity()
        let metadata = StoredSecretMetadata(cacheSeconds: 0, createdAt: Date(), lastAccessAt: nil)
        guard FileManager.default.fileExists(atPath: fileUrl.path) else {
            recordFileRead(identity: identity, filePath: fileUrl.path, result: "not_found", metadata: metadata)
            return .failure(ServiceError(code: "not_found", message: "File not found"))
        }

        let encoded: Data
        do {
            encoded = try Data(contentsOf: fileUrl)
        } catch {
            recordFileRead(identity: identity, filePath: fileUrl.path, result: "read_failed", metadata: metadata)
            return .failure(ServiceError(code: "read_failed", message: "Failed to read file"))
        }

        let payload: FileCryptoPayload
        do {
            payload = try FileCrypto.decodePayload(encoded)
        } catch {
            recordFileRead(identity: identity, filePath: fileUrl.path, result: "invalid_payload", metadata: metadata)
            return .failure(ServiceError(code: "invalid_payload", message: "Invalid file payload"))
        }

        switch payload {
        case .plaintext(let plaintext):
            let response = FileReadResponse(plaintext: String(data: plaintext, encoding: .utf8) ?? "")
            recordFileRead(identity: identity, filePath: fileUrl.path, result: "success", metadata: nil)
            return .success(response)
        case .encrypted(let encrypted):
            let keyResponse: SecretAccessResponse
            do {
                keyResponse = try fetchFileKey(name: encrypted.keyName, reason: request.reason, filePath: fileUrl.path)
            } catch let error as ServiceError {
                recordFileRead(identity: identity, filePath: fileUrl.path, result: "key_fetch_failed", metadata: nil)
                return .failure(error)
            } catch {
                recordFileRead(identity: identity, filePath: fileUrl.path, result: "key_fetch_failed", metadata: nil)
                return .failure(ServiceError(code: "key_fetch_failed", message: "Failed to fetch key"))
            }

            guard let keyData = Data(base64Encoded: keyResponse.secretValue) else {
                recordFileRead(identity: identity, filePath: fileUrl.path, result: "invalid_key", metadata: nil)
                return .failure(ServiceError(code: "invalid_key", message: "Invalid key payload"))
            }
            let key = SymmetricKey(data: keyData)
            do {
                let plaintext = try FileCrypto.decryptPayload(encrypted, key: key)
                let response = FileReadResponse(plaintext: String(data: plaintext, encoding: .utf8) ?? "")
                recordFileRead(identity: identity, filePath: fileUrl.path, result: "success", metadata: nil)
                return .success(response)
            } catch {
                recordFileRead(identity: identity, filePath: fileUrl.path, result: "decrypt_failed", metadata: nil)
                return .failure(ServiceError(code: "decrypt_failed", message: "Failed to decrypt file"))
            }
        }
    }

    func healthStatus() -> HealthResponse {
        return HealthResponse(version: "0.1.0", uptime: Date().timeIntervalSince(startDate))
    }

    private func fetchFileKey(name: String, reason: String?, filePath: String) throws -> SecretAccessResponse {
        let keyRequest = SecretAccessRequest(name: name, reason: nil)
        let keyMetadata = loadMetadata(for: name)
        guard keyMetadata != nil else {
            throw ServiceError(code: "not_found", message: "File key not found")
        }
        let accessReason: String
        if let reason, !reason.isEmpty {
            accessReason = "file.decrypt:\(filePath) \(reason)"
        } else {
            accessReason = "file.decrypt:\(filePath)"
        }
        return try fetchSecretWithAuth(request: keyRequest, reason: accessReason)
    }

    private func fetchSecretWithAuth(request: SecretAccessRequest, reason: String) throws -> SecretAccessResponse {
        let metadata = loadMetadata(for: request.name)
        guard let metadata else {
            throw ServiceError(code: "not_found", message: "Unknown secret")
        }
        let identity = policy.resolveClientIdentity()
        let requiresAuth = !cache.hasValidCache(for: identity.cdhash, secretName: request.name)
        var authSatisfied = false
        if requiresAuth {
            let prompt = authPrompt(identity: identity, request: SecretAccessRequest(name: request.name, reason: reason))
            authSatisfied = auth.evaluate(prompt: prompt)
            if !authSatisfied {
                recordAccess(identity: identity, secretName: request.name, result: "auth_failed", metadata: metadata)
                throw ServiceError(code: "auth_failed", message: "Authentication failed")
            }
            cache.storeCache(for: identity.cdhash, secretName: request.name, cacheSeconds: metadata.cacheSeconds)
        }
        let storedName = storedName(for: request.name)
        guard let secret = keychain.readSecret(name: storedName) else {
            recordAccess(identity: identity, secretName: request.name, result: "not_found", metadata: metadata)
            throw ServiceError(code: "not_found", message: "Secret missing in keychain")
        }
        policy.recordAccess(name: request.name)
        let response = SecretAccessResponse(secretValue: secret, cacheSeconds: metadata.cacheSeconds, authRequired: requiresAuth, authSatisfied: authSatisfied || !requiresAuth)
        recordAccess(identity: identity, secretName: request.name, result: "success", metadata: metadata)
        return response
    }

    private func authPrompt(identity: ClientIdentity, request: SecretAccessRequest) -> String {
        let description = "\(identity.binaryName) (\(identity.binaryPath))"
        if let reason = request.reason, reason.hasPrefix("file.decrypt:") {
            let filePath = reason.replacingOccurrences(of: "file.decrypt:", with: "")
            return "decrypt file \(filePath) for \(description)"
        }
        return "access secret \(request.name) for \(description)"
    }

    private func recordAccess(identity: ClientIdentity, secretName: String, result: String, metadata: StoredSecretMetadata) {
        let event = AuditEvent(
            requestId: UUID(),
            timestamp: Date(),
            client: identity,
            action: "secret.access",
            secretName: secretName,
            result: result,
            metadata: ["cache_seconds": String(metadata.cacheSeconds)]
        )
        auditLogger.log(event)
        notificationBridge.postSecretAccess(event: event)
    }

    private func recordFileRead(identity: ClientIdentity, filePath: String, result: String, metadata: StoredSecretMetadata?) {
        let event = AuditEvent(
            requestId: UUID(),
            timestamp: Date(),
            client: identity,
            action: "file.read",
            secretName: filePath,
            result: result,
            metadata: metadata.map { ["cache_seconds": String($0.cacheSeconds)] }
        )
        auditLogger.log(event)
        notificationBridge.postSecretAccess(event: event)
    }
}
