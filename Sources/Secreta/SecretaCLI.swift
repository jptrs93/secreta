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

        let positionals = positionalArguments(arguments: Array(arguments.dropFirst()))

        switch command {
        case "create":
            handleCreate(client: client, options: options)
        case "fetch":
            handleFetch(client: client, options: options)
        case "delete":
            handleDelete(client: client, options: options)
        case "status":
            handleStatus(client: client)
        case "file":
            handleFile(client: client, arguments: positionals)
        default:
            printUsage()
        }
    }

    private static func handleFile(client: SecretaClient, arguments: [String]) {
        guard let subcommand = arguments.first, subcommand == "edit" else {
            printUsage()
            return
        }
        guard arguments.count > 1 else {
            printUsage()
            return
        }
        let path = arguments[1]

        do {
            let editor = DefaultEditor()
            let fileEditor = FileEditor(client: client, editor: editor)
            let resolvedPath = try fileEditor.edit(path: path)
            print("encrypted \(resolvedPath.path)")
        } catch FileEditorError.noTTY {
            print("no TTY detected; set EDITOR/VISUAL to a GUI editor with --wait")
        } catch {
            print("\(error)")
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

    private static func handleDelete(client: SecretaClient, options: [String: String]) {
        guard let name = options["--name"] else {
            printUsage()
            return
        }

        do {
            let response = try client.deleteSecret(name: name)
            if response.deleted {
                print("deleted secret \(name)")
            } else {
                print("failed to delete \(name)")
            }
        } catch {
            print("\(error)")
        }
    }

    private static func handleStatus(client: SecretaClient) {
        do {
            let response = try client.healthStatus()
            print("ok version=\(response.version) uptime=\(Int(response.uptime))s")
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

    private static func positionalArguments(arguments: [String]) -> [String] {
        var positionals: [String] = []
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument.hasPrefix("--") {
                let nextIndex = index + 1
                if nextIndex < arguments.count {
                    index += 2
                } else {
                    index += 1
                }
                continue
            }
            positionals.append(argument)
            index += 1
        }
        return positionals
    }

    static func printUsage() {
        print("secreta <command> [options]")
        print("commands:")
        print("  create --name <name> --value <value> [--cache-seconds <seconds>] [--socket <path>] [--timeout <seconds>]")
        print("  fetch --name <name> [--reason <reason>] [--socket <path>] [--timeout <seconds>]")
        print("  delete --name <name> [--socket <path>] [--timeout <seconds>]")
        print("  status [--socket <path>] [--timeout <seconds>]")
        print("  file edit <path> [--socket <path>] [--timeout <seconds>]")
        print("  daemon run")
    }
}
