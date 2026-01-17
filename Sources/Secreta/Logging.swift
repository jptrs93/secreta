import Foundation
import os.log

enum LoggerFactory {
    static let subsystem = "com.example.secreta"

    static func make(_ category: String) -> Logger {
        return Logger(subsystem: subsystem, category: category)
    }
}

struct AuditEvent: Codable {
    let requestId: UUID
    let timestamp: Date
    let client: ClientIdentity
    let action: String
    let secretName: String
    let result: String
    let metadata: [String: String]?
}

final class AuditLogger {
    private let logger = LoggerFactory.make("audit")

    func log(_ event: AuditEvent) {
        if let data = try? JSONEncoder().encode(event),
           let payload = String(data: data, encoding: .utf8) {
            logger.info("audit=")
            logger.info("\(payload, privacy: .private)")
        } else {
            logger.info("audit=failed_to_encode")
        }
    }
}

final class NotificationCenterBridge {
    private let notificationCenter = DistributedNotificationCenter.default()

    func postSecretAccess(event: AuditEvent) {
        let name = Notification.Name("com.example.secreta.access")
        var userInfo: [String: Any] = [
            "request_id": event.requestId.uuidString,
            "client_name": event.client.binaryName,
            "client_path": event.client.binaryPath,
            "secret_name": event.secretName,
            "result": event.result,
            "timestamp": event.timestamp.timeIntervalSince1970
        ]
        if let metadata = event.metadata {
            userInfo["metadata"] = metadata
        }
        notificationCenter.post(name: name, object: nil, userInfo: userInfo)
    }
}
