import Foundation

struct SecretaCLI {
    static func run(arguments: [String]) {
        guard let command = arguments.first else {
            printUsage()
            return
        }

        var options = parseOptions(arguments: Array(arguments.dropFirst()))
        let socketPath = options.removeValue(forKey: "--socket") ?? AppConfig.defaultConfig().socketPath
        let timeoutSeconds = options.removeValue(forKey: "--timeout").flatMap(Double.init) ?? 30
        let client = SecretaClient(socketPath: socketPath, timeout: timeoutSeconds)

        switch command {
        case "create":
            handleCreate(client: client, options: options)
        case "fetch":
            handleFetch(client: client, options: options)
        default:
            printUsage()
        }
    }

    private static func handleCreate(client: SecretaClient, options: [String: String]) {
        guard let name = options["--name"], let value = options["--value"] else {
            printUsage()
            return
        }
        let cacheSeconds = options["--cache-seconds"].flatMap(Int.init)

        do {
            let response = try client.createSecret(name: name, secretValue: value, cacheSeconds: cacheSeconds)
            print("created secret \(response.storedName) (cache \(response.cacheSeconds)s)")
        } catch {
            print("\(error)")
        }
    }

    private static func handleFetch(client: SecretaClient, options: [String: String]) {
        guard let name = options["--name"] else {
            printUsage()
            return
        }
        let reason = options["--reason"]

        do {
            let response = try client.fetchSecret(name: name, reason: reason)
            print(response.secretValue)
        } catch {
            print("\(error)")
        }
    }

    private static func parseOptions(arguments: [String]) -> [String: String] {
        var options: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            guard argument.hasPrefix("--") else {
                index += 1
                continue
            }
            let nextIndex = index + 1
            if nextIndex < arguments.count {
                options[argument] = arguments[nextIndex]
                index += 2
            } else {
                options[argument] = ""
                index += 1
            }
        }
        return options
    }

    private static func printUsage() {
        print("secreta secret <command> [options]")
        print("commands:")
        print("  create --name <name> --value <value> [--cache-seconds <seconds>] [--socket <path>] [--timeout <seconds>]")
        print("  fetch --name <name> [--reason <reason>] [--socket <path>] [--timeout <seconds>]")
    }
}
