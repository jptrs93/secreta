import XCTest
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
}
