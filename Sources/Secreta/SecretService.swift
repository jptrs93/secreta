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
        let storedName = "sm:\(cacheSeconds):\(request.name)"
        let secretId = UUID().uuidString
        let metadata = StoredSecretMetadata(cacheSeconds: cacheSeconds, createdAt: Date(), lastAccessAt: nil)
        keychain.storeSecret(name: storedName, secret: request.secretValue, metadata: metadata)
        policy.recordSecret(name: request.name, metadata: metadata)
        return SecretCreateResponse(secretId: secretId, storedName: storedName, cacheSeconds: cacheSeconds)
    }

    func accessSecret(request: SecretAccessRequest) -> Result<SecretAccessResponse, ServiceError> {
        guard let metadata = policy.metadata(for: request.name) else {
            return .failure(ServiceError(code: "not_found", message: "Unknown secret"))
        }
        let identity = policy.resolveClientIdentity()
        let requiresAuth = !cache.hasValidCache(for: identity.cdhash, secretName: request.name)
        var authSatisfied = false
        if requiresAuth {
            let prompt = "\(identity.binaryName) is requesting access to \(request.name)"
            authSatisfied = auth.evaluate(prompt: prompt)
            if !authSatisfied {
                recordAccess(identity: identity, secretName: request.name, result: "auth_failed", metadata: metadata)
                return .failure(ServiceError(code: "auth_failed", message: "Authentication failed"))
            }
            cache.storeCache(for: identity.cdhash, secretName: request.name, cacheSeconds: metadata.cacheSeconds)
        }
        guard let secret = keychain.readSecret(name: "sm:\(metadata.cacheSeconds):\(request.name)") else {
            recordAccess(identity: identity, secretName: request.name, result: "not_found", metadata: metadata)
            return .failure(ServiceError(code: "not_found", message: "Secret missing in keychain"))
        }
        policy.recordAccess(name: request.name)
        let response = SecretAccessResponse(secretValue: secret, cacheSeconds: metadata.cacheSeconds, authRequired: requiresAuth, authSatisfied: authSatisfied || !requiresAuth)
        recordAccess(identity: identity, secretName: request.name, result: "success", metadata: metadata)
        return .success(response)
    }

    func secretMeta(name: String) -> Result<SecretMetaResponse, ServiceError> {
        guard let metadata = policy.metadata(for: name) else {
            return .failure(ServiceError(code: "not_found", message: "Unknown secret"))
        }
        let response = SecretMetaResponse(cacheSeconds: metadata.cacheSeconds, lastAccessAt: metadata.lastAccessAt, createdAt: metadata.createdAt)
        return .success(response)
    }

    func healthStatus() -> HealthResponse {
        return HealthResponse(version: "0.1.0", uptime: Date().timeIntervalSince(startDate))
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
