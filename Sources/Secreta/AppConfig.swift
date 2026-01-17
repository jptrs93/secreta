import Foundation

struct AppConfig {
    let socketPath: String
    let bundleIdentifier: String

    static func defaultConfig() -> AppConfig {
        return AppConfig(
            socketPath: "/tmp/secreta.sock",
            bundleIdentifier: "com.example.secreta"
        )
    }
}
