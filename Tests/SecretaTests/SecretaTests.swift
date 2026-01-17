import XCTest
import Darwin
@testable import Secreta

final class SecretaTests: XCTestCase {
    func testHealthResponse() {
        let keychain = KeychainAdapter()
        let cache = CacheManager()
        let policy = PolicyEngine()
        let audit = AuditLogger()
        let notificationBridge = NotificationCenterBridge()
        let auth = AuthChallenge()
        let service = SecretService(
            keychain: keychain,
            cache: cache,
            policy: policy,
            auditLogger: audit,
            notificationBridge: notificationBridge,
            auth: auth
        )
        let response = service.healthStatus()
        XCTAssertGreaterThanOrEqual(response.uptime, 0)
    }

    func testSocketCreateDelete() throws {
        let socketPath = "/tmp/secreta-test-\(UUID().uuidString).sock"
        let keychain = KeychainAdapter()
        let cache = CacheManager()
        let policy = PolicyEngine()
        let audit = AuditLogger()
        let notificationBridge = NotificationCenterBridge()
        let auth = AuthChallenge()
        let service = SecretService(
            keychain: keychain,
            cache: cache,
            policy: policy,
            auditLogger: audit,
            notificationBridge: notificationBridge,
            auth: auth
        )
        let router = SecretRequestRouter(service: service)
        let server = try SocketServer(socketPath: socketPath, handler: router)
        server.start()

        defer {
            _ = try? FileManager.default.removeItem(atPath: socketPath)
        }

        waitForSocket(at: socketPath)

        let client = SecretaClient(socketPath: socketPath, timeout: 2)
        let secretName = "test-\(UUID().uuidString)"
        let createResponse = try client.createSecret(name: secretName, secretValue: "test", cacheSeconds: 0)
        defer {
            _ = keychain.deleteSecret(name: createResponse.storedName)
        }

        let deleteResponse = try client.deleteSecret(name: secretName)
        XCTAssertTrue(deleteResponse.deleted)
    }

    private func waitForSocket(at path: String) {
        for _ in 0..<50 {
            if FileManager.default.fileExists(atPath: path) {
                return
            }
            usleep(50_000)
        }
    }
}
