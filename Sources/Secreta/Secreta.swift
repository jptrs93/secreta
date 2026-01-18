import Foundation

@main
struct SecretaApp {
    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count > 1 else {
            SecretaCLI.printUsage()
            return
        }

        let command = arguments[1]
        if command == "daemon" {
            if arguments.count > 2, arguments[2] == "run" {
                startDaemon()
            } else {
                SecretaCLI.printUsage()
            }
            return
        }

        SecretaCLI.run(arguments: Array(arguments.dropFirst()))
    }

    private static func startDaemon() {
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
            let server = try SocketServer(socketPath: config.socketPath, handler: router, identitySink: policy)
            logger.info("starting secreta socket on \(config.socketPath)")
            logger.info("secreta daemon pid=\(ProcessInfo.processInfo.processIdentifier)")
            server.start()
            RunLoop.current.run()
        } catch {
            logger.error("socket_start_failed=\(error.localizedDescription)")
        }
    }
}
