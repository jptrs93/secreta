import Foundation
import LocalAuthentication

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

    func healthStatus() -> HealthResponse {
        return HealthResponse(version: "0.1.0", uptime: Date().timeIntervalSince(startDate))
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
}
