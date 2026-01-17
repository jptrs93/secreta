import CryptoKit
import CryptoKit
import Darwin
import Foundation
import Security

protocol FileEditorClient {
    func createRawSecret(name: String, secretValue: String) throws -> SecretCreateResponse
    func fetchRawSecret(name: String, reason: String?) throws -> SecretAccessResponse
}

extension SecretaClient: FileEditorClient {}

final class FileEditor {
    private let client: FileEditorClient
    private let editor: EditorRunner

    init(client: FileEditorClient, editor: EditorRunner) {
        self.client = client
        self.editor = editor
    }

    func edit(path: String) throws -> URL {
        if !TerminalChecker.isInteractive() {
            throw FileEditorError.noTTY
        }
        let filePath = try resolvePath(path)
        let state = try loadState(filePath: filePath)

        let tempUrl = try createTempFile(plaintext: state.plaintext)
        defer {
            cleanupTempFile(url: tempUrl)
        }

        try editor.open(path: tempUrl.path)

        let editedData = try Data(contentsOf: tempUrl)
        try encryptAndWrite(
            plaintext: editedData,
            keyName: state.keyName,
            keyData: state.key,
            destination: filePath
        )
        return filePath
    }

    private func resolvePath(_ path: String) throws -> URL {
        let inputUrl = URL(fileURLWithPath: path)
        let absoluteUrl = inputUrl.isFileURL && inputUrl.path.hasPrefix("/")
            ? inputUrl
            : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent(path)
        return absoluteUrl.standardizedFileURL.resolvingSymlinksInPath()
    }

    private struct FileState {
        let keyName: String
        let key: SymmetricKey
        let plaintext: Data
    }

    private func loadState(filePath: URL) throws -> FileState {
        guard FileManager.default.fileExists(atPath: filePath.path) else {
            return try newFileState(plaintext: Data())
        }
        let encoded = try Data(contentsOf: filePath)
        guard !encoded.isEmpty else {
            return try newFileState(plaintext: Data())
        }
        guard let decoded = Data(base64Encoded: encoded) else {
            return try newFileState(plaintext: encoded)
        }
        let magic = Data("SEFT".utf8)
        if !decoded.starts(with: magic) {
            return try newFileState(plaintext: encoded)
        }
        guard decoded.count > 21 else {
            throw FileEditorError.invalidPayload
        }
        let version = decoded[4]
        guard version == 2 else {
            throw FileEditorError.unsupportedVersion
        }
        let keyNameLength = decoded[5]
        guard keyNameLength > 0 else {
            throw FileEditorError.invalidPayload
        }
        let keyStart = 6
        let keyEnd = keyStart + Int(keyNameLength)
        guard decoded.count > keyEnd + 12 + 16 else {
            throw FileEditorError.invalidPayload
        }
        let keyNameData = decoded[keyStart..<keyEnd]
        guard let keyName = String(data: keyNameData, encoding: .utf8) else {
            throw FileEditorError.invalidPayload
        }
        let nonceStart = keyEnd
        let nonceEnd = nonceStart + 12
        let nonceData = Data(decoded[nonceStart..<nonceEnd])
        let ciphertext = Data(decoded[nonceEnd...])
        guard ciphertext.count > 16 else {
            throw FileEditorError.invalidPayload
        }
        let keyData = try fetchExistingKey(name: keyName, reason: "file.decrypt:\(filePath.path)")
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertext.dropLast(16)),
            tag: Data(ciphertext.suffix(16))
        )
        let plaintext = try AES.GCM.open(sealedBox, using: keyData)
        return FileState(keyName: keyName, key: keyData, plaintext: plaintext)
    }

    private func newFileState(plaintext: Data) throws -> FileState {
        let keyName = try createKeyName()
        let keyData = try loadOrCreateKey(name: keyName)
        return FileState(keyName: keyName, key: keyData, plaintext: plaintext)
    }

    private func createKeyName() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw FileEditorError.keyGenerationFailed
        }
        let data = Data(bytes)
        let keyId = data.base64EncodedString()
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        return "sa:ek_\(keyId)"
    }

    private func fetchExistingKey(name: String, reason: String?) throws -> SymmetricKey {
        let existing = try client.fetchRawSecret(name: name, reason: reason)
        guard let data = Data(base64Encoded: existing.secretValue) else {
            throw FileEditorError.invalidKey
        }
        return SymmetricKey(data: data)
    }

    private func loadOrCreateKey(name: String) throws -> SymmetricKey {
        do {
            return try fetchExistingKey(name: name, reason: nil)
        } catch let error as ClientError {
            if case let .remoteError(code, _) = error, code != "not_found" {
                throw error
            }
        } catch {
            throw error
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw FileEditorError.keyGenerationFailed
        }
        let data = Data(bytes)
        _ = try client.createRawSecret(name: name, secretValue: data.base64EncodedString())
        return SymmetricKey(data: data)
    }

    private func encryptAndWrite(plaintext: Data, keyName: String, keyData: SymmetricKey, destination: URL) throws {
        guard let keyNameData = keyName.data(using: .utf8) else {
            throw FileEditorError.invalidPayload
        }
        guard keyNameData.count <= 255 else {
            throw FileEditorError.invalidPayload
        }
        let sealedBox = try AES.GCM.seal(plaintext, using: keyData)
        let header = Data("SEFT".utf8) + Data([2, UInt8(keyNameData.count)]) + keyNameData
        let payload = header + Data(sealedBox.nonce) + sealedBox.ciphertext + sealedBox.tag
        let encoded = payload.base64EncodedData()

        let directory = destination.deletingLastPathComponent()
        let tempUrl = directory.appendingPathComponent(".secreta-tmp-\(UUID().uuidString)")
        try encoded.write(to: tempUrl, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempUrl.path)
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: tempUrl)
        } else {
            try FileManager.default.moveItem(at: tempUrl, to: destination)
        }
    }

    private func createTempFile(plaintext: Data) throws -> URL {
        let tempUrl = FileManager.default.temporaryDirectory
            .appendingPathComponent("secreta-edit-\(UUID().uuidString)")
        let created = FileManager.default.createFile(
            atPath: tempUrl.path,
            contents: plaintext,
            attributes: [.posixPermissions: 0o600]
        )
        if !created {
            throw FileEditorError.tempFileCreationFailed
        }
        return tempUrl
    }

    private func cleanupTempFile(url: URL) {
        if let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attributes[.size] as? NSNumber {
            let zeros = Data(repeating: 0, count: size.intValue)
            try? zeros.write(to: url, options: .atomic)
        }
        try? FileManager.default.removeItem(at: url)
    }
}

enum FileEditorError: Error {
    case editorFailed(status: Int32)
    case invalidKey
    case invalidPayload
    case keyGenerationFailed
    case noTTY
    case tempFileCreationFailed
    case unsupportedVersion
}

protocol EditorRunner {
    func open(path: String) throws
}

enum TerminalChecker {
    static func isInteractive() -> Bool {
        return isatty(fileno(stdin)) != 0
            && isatty(fileno(stdout)) != 0
            && isatty(fileno(stderr)) != 0
    }
}

struct DefaultEditor: EditorRunner {
    func open(path: String) throws {
        let editorPath = resolveEditorPath()
        let command = [editorPath, path].joined(separator: " ")
        print("opening editor: \(command)")
        let status = try spawnAndWait(executable: editorPath, arguments: [path])
        if status != 0 {
            throw FileEditorError.editorFailed(status: status)
        }
    }

    private func spawnAndWait(executable: String, arguments: [String]) throws -> Int32 {
        let parts = executable.split(separator: " ").map(String.init)
        guard let resolved = parts.first else {
            throw FileEditorError.editorFailed(status: 1)
        }
        let allArguments = Array(parts.dropFirst()) + arguments

        var argv = [UnsafeMutablePointer<CChar>?]()
        argv.append(strdup(resolved))
        for argument in allArguments {
            argv.append(strdup(argument))
        }
        argv.append(nil)
        defer {
            for pointer in argv where pointer != nil {
                free(pointer)
            }
        }

        var pid: pid_t = 0
        let result = posix_spawn(&pid, resolved, nil, nil, argv, environ)
        guard result == 0 else {
            throw FileEditorError.editorFailed(status: Int32(result))
        }

        var status: Int32 = 0
        if waitpid(pid, &status, 0) == -1 {
            throw FileEditorError.editorFailed(status: Int32(errno))
        }
        return status
    }

    private func resolveEditorPath() -> String {
        if let value = ProcessInfo.processInfo.environment["EDITOR"], !value.isEmpty {
            return value
        }
        if let value = ProcessInfo.processInfo.environment["VISUAL"], !value.isEmpty {
            return value
        }
        return "/usr/bin/vi"
    }
}
