import Foundation
import CryptoKit
import Security
import Darwin

protocol ClientIdentitySink {
    func updateClientIdentity(_ identity: ClientIdentity)
}

enum SocketError: Error {
    case createFailed
    case bindFailed
    case listenFailed
}

final class SocketServer: @unchecked Sendable {
    private let listenerFd: Int32
    private let socketPath: String
    private let queue = DispatchQueue(label: "secreta.socket")
    private let logger = LoggerFactory.make("socket")
    private let handler: RequestHandler
    private let identitySink: ClientIdentitySink
    private var acceptSource: DispatchSourceRead?

    init(socketPath: String, handler: RequestHandler, identitySink: ClientIdentitySink) throws {
        self.handler = handler
        self.identitySink = identitySink
        self.socketPath = socketPath
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw SocketError.createFailed
        }
        listenerFd = fd
        try bindAndListen()
    }

    deinit {
        if listenerFd >= 0 {
            close(listenerFd)
        }
    }

    func start() {
        let source = DispatchSource.makeReadSource(fileDescriptor: listenerFd, queue: queue)
        source.setEventHandler { [weak self] in
            self?.acceptConnection()
        }
        source.setCancelHandler { [weak self] in
            if let fd = self?.listenerFd, fd >= 0 {
                close(fd)
            }
        }
        acceptSource = source
        source.resume()
        logger.info("listener_ready socket_path=\(self.socketPath, privacy: .public)")
    }

    private func bindAndListen() throws {
        unlink(socketPath)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let maxLength = MemoryLayout.size(ofValue: address.sun_path) - 1
        _ = socketPath.withCString { pointer in
            withUnsafeMutablePointer(to: &address.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: maxLength) { dest in
                    strncpy(dest, pointer, maxLength)
                }
            }
        }
        let baseLength = MemoryLayout<sockaddr_un>.size
        let nameLength = socketPath.utf8.count + 1
        let length = socklen_t(baseLength - MemoryLayout.size(ofValue: address.sun_path) + nameLength)
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
                bind(listenerFd, pointer, length)
            }
        }
        guard bindResult == 0 else {
            throw SocketError.bindFailed
        }
        guard listen(listenerFd, SOMAXCONN) == 0 else {
            throw SocketError.listenFailed
        }
    }

    private func acceptConnection() {
        var address = sockaddr()
        var length: socklen_t = socklen_t(MemoryLayout<sockaddr>.size)
        let clientFd = accept(listenerFd, &address, &length)
        guard clientFd >= 0 else {
            logger.error("accept_failed")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.handleConnection(fd: clientFd)
        }
    }

    private func handleConnection(fd: Int32) {
        defer {
            close(fd)
        }
        let identity = resolveIdentity(fd: fd)
        identitySink.updateClientIdentity(identity)
        while true {
            guard let payload = readPayload(fd: fd) else {
                return
            }
            handler.handle(payload: payload) { responseData in
                let framed = self.frame(responseData)
                _ = self.writeFully(fd: fd, data: framed)
            }
        }
    }

    private func readPayload(fd: Int32) -> Data? {
        var lengthBytes = [UInt8](repeating: 0, count: MemoryLayout<UInt32>.size)
        guard readFully(fd: fd, buffer: &lengthBytes, expected: lengthBytes.count) else {
            return nil
        }
        let length = lengthBytes.withUnsafeBytes { $0.load(as: UInt32.self) }
        if length == 0 {
            return Data()
        }
        var payloadBytes = [UInt8](repeating: 0, count: Int(length))
        guard readFully(fd: fd, buffer: &payloadBytes, expected: payloadBytes.count) else {
            return nil
        }
        return Data(payloadBytes)
    }

    private func readFully(fd: Int32, buffer: inout [UInt8], expected: Int) -> Bool {
        var totalRead = 0
        while totalRead < expected {
            let readCount = buffer.withUnsafeMutableBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return -1
                }
                return read(fd, baseAddress.advanced(by: totalRead), expected - totalRead)
            }
            if readCount <= 0 {
                return false
            }
            totalRead += readCount
        }
        return true
    }

    private func writeFully(fd: Int32, data: Data) -> Bool {
        var totalWritten = 0
        while totalWritten < data.count {
            let writeCount = data.withUnsafeBytes { rawBuffer in
                guard let baseAddress = rawBuffer.baseAddress else {
                    return -1
                }
                return write(fd, baseAddress.advanced(by: totalWritten), data.count - totalWritten)
            }
            if writeCount <= 0 {
                return false
            }
            totalWritten += writeCount
        }
        return true
    }

    private func frame(_ data: Data) -> Data {
        var length = UInt32(data.count)
        let lengthData = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        return lengthData + data
    }

    private func resolveIdentity(fd: Int32) -> ClientIdentity {
        let peerPid = peerPidForConnection(fd: fd)
        guard peerPid > 0 else {
            return ClientIdentity(cdhash: "unknown", binaryName: "unknown", binaryPath: "unknown")
        }
        guard let binaryPath = binaryPathForPid(peerPid) else {
            return ClientIdentity(cdhash: "unknown", binaryName: "unknown", binaryPath: "unknown")
        }
        let binaryName = URL(fileURLWithPath: binaryPath).lastPathComponent
        let cdhash = cdhashForBinary(path: binaryPath)
        let fallbackHash = cdhash ?? sha1ForBinary(path: binaryPath)
        let resolvedHash = fallbackHash ?? "unknown"
        let signatureStatus = cdhash == nil ? "unsigned" : "signed"
        logger.info("identity_signature=\(signatureStatus, privacy: .public)")
        return ClientIdentity(cdhash: resolvedHash, binaryName: binaryName, binaryPath: binaryPath)
    }

    private func peerPidForConnection(fd: Int32) -> pid_t {
        var pid = pid_t()
        var size = socklen_t(MemoryLayout<pid_t>.size)
        if getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) != 0 {
            return 0
        }
        return pid
    }

    private func binaryPathForPid(_ pid: pid_t) -> String? {
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else {
            return nil
        }
        let pathData = Data(buffer.prefix(Int(length)))
        return String(data: pathData, encoding: .utf8)
    }

    private func cdhashForBinary(path: String) -> String? {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return nil
        }
        var information: CFDictionary?
        let status = SecCodeCopySigningInformation(code, [], &information)
        guard status == errSecSuccess,
              let info = information as? [String: Any],
              let cdhashData = info["cdhash"] as? Data else {
            return nil
        }
        return cdhashData.map { String(format: "%02x", $0) }.joined()
    }

    private func sha1ForBinary(path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        let digest = Insecure.SHA1.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
