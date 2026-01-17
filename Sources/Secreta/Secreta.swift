import Foundation

@main
struct SecretaApp {
    static func main() {
        let arguments = CommandLine.arguments
        if arguments.count > 1, arguments[1] == "secret" {
            SecretaCLI.run(arguments: Array(arguments.dropFirst(2)))
            return
        }

        let config = AppConfig.defaultConfig()
        let logger = LoggerFactory.make("main")
        let keychain = KeychainAdapter()
        let cache = CacheManager()
        let policy = PolicyEngine()
        let auditLogger = AuditLogger()
        let notificationBridge = NotificationCenterBridge()
        let auth = AuthChallenge()
        let service = SecretService(
            keychain: keychain,
            cache: cache,
            policy: policy,
            auditLogger: auditLogger,
            notificationBridge: notificationBridge,
            auth: auth
        )
        let router = SecretRequestRouter(service: service)

        do {
            let server = try SocketServer(socketPath: config.socketPath, handler: router)
            logger.info("starting secreta socket on \(config.socketPath)")
            server.start()
            RunLoop.current.run()
        } catch {
            logger.error("socket_start_failed=\(error.localizedDescription)")
        }
    }
}
