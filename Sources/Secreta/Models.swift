import Foundation

struct ClientIdentity: Codable {
    let cdhash: String
    let binaryName: String
    let binaryPath: String
}

struct RequestEnvelope: Codable {
    let requestId: UUID
    let method: String
    let params: Data
}

struct ResponseEnvelope: Codable {
    let requestId: UUID
    let result: Data?
    let error: ErrorEnvelope?
}

struct ErrorEnvelope: Codable {
    let code: String
    let message: String
    let retryable: Bool
    let details: [String: String]?
}

struct SecretCreateRequest: Codable {
    let name: String
    let secretValue: String
    let cacheSeconds: Int?
    let metadata: [String: String]?
}

struct SecretCreateResponse: Codable {
    let secretId: String
    let storedName: String
    let cacheSeconds: Int
}

struct SecretAccessRequest: Codable {
    let name: String
    let reason: String?
}

struct SecretAccessResponse: Codable {
    let secretValue: String
    let cacheSeconds: Int
    let authRequired: Bool
    let authSatisfied: Bool
}

struct SecretMetaResponse: Codable {
    let cacheSeconds: Int
    let lastAccessAt: Date?
    let createdAt: Date
}

struct HealthResponse: Codable {
    let version: String
    let uptime: TimeInterval
}

struct StoredSecretMetadata: Codable {
    let cacheSeconds: Int
    let createdAt: Date
    var lastAccessAt: Date?
}

struct CachedAccessRecord {
    let clientCdhash: String
    let secretName: String
    let expiresAt: Date
}
