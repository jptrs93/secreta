import Foundation
import os.log
import UserNotifications

enum LoggerFactory {
    static let subsystem = "com.secreta"

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
        var details = ""
        if let metadata = event.metadata,
           let cacheSeconds = metadata["cache_seconds"] {
            details = " cache_seconds=\(cacheSeconds)"
        }
        logger.info("audit action=\(event.action, privacy: .public) secret=\(event.secretName, privacy: .public) result=\(event.result, privacy: .public) client=\(event.client.binaryName, privacy: .public)\(details, privacy: .public)")
    }
}

final class NotificationCenterBridge {
    private let notificationCenter = UNUserNotificationCenter.current()
    private let logger = LoggerFactory.make("notification")

    init() {
        let logger = logger
        notificationCenter.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error {
                let nsError = error as NSError
                logger.error("notification_auth_error domain=\(nsError.domain, privacy: .public) code=\(nsError.code, privacy: .public) desc=\(nsError.localizedDescription, privacy: .public)")
            } else {
                logger.info("notification_auth_granted=\(granted)")
            }
        }
    }

    func postSecretAccess(event: AuditEvent) {
        let content = UNMutableNotificationContent()
        content.title = "Secreta Audit"
        content.subtitle = event.action
        content.body = "\(event.client.binaryName) \(event.result) \(event.secretName)"
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: event.requestId.uuidString,
            content: content,
            trigger: nil
        )
        let logger = logger
        notificationCenter.add(request) { error in
            if let error {
                let nsError = error as NSError
                logger.error("notification_post_error domain=\(nsError.domain, privacy: .public) code=\(nsError.code, privacy: .public) desc=\(nsError.localizedDescription, privacy: .public)")
            } else {
                logger.info("notification_posted=\(event.action, privacy: .public)")
            }
        }
    }
}
