import Foundation
import Network
import Security
import Darwin

protocol ClientIdentitySink {
    func updateClientIdentity(_ identity: ClientIdentity)
}

final class SocketServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "secreta.socket")
    private let logger = LoggerFactory.make("socket")
    private let handler: RequestHandler
    private let identitySink: ClientIdentitySink

    init(socketPath: String, handler: RequestHandler, identitySink: ClientIdentitySink) throws {
        self.handler = handler
        self.identitySink = identitySink
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = NWEndpoint.unix(path: socketPath)
        listener = try NWListener(using: params)
    }

    func start() {
        listener.newConnectionHandler = { [weak self] connection in
            self?.setupConnection(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            self?.logger.info("listener_state=\(String(describing: state))")
        }
        listener.start(queue: queue)
    }

    private func setupConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = { [weak self] state in
            self?.logger.info("connection_state=\(String(describing: state))")
        }
        receive(on: connection)
        connection.start(queue: queue)
    }

    private func receive(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 4, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let error = error {
                self.logger.error("receive_error=\(error.localizedDescription)")
                connection.cancel()
                return
            }
            if isComplete {
                connection.cancel()
                return
            }
            guard let data = data, data.count >= 4 else {
                self.receive(on: connection)
                return
            }
            let payload = self.readLengthPrefixedPayload(data)
            self.handlePayload(payload, on: connection)
        }
    }

    private func readLengthPrefixedPayload(_ data: Data) -> Data {
        let lengthData = data.prefix(4)
        let length = lengthData.withUnsafeBytes { $0.load(as: UInt32.self) }
        let payload = data.dropFirst(4)
        if payload.count >= Int(length) {
            return payload.prefix(Int(length))
        }
        return payload
    }

    private func handlePayload(_ payload: Data, on connection: NWConnection) {
        if let identity = resolveIdentity(connection: connection) {
            identitySink.updateClientIdentity(identity)
        }
        handler.handle(payload: payload) { [weak self] responseData in
            guard let self = self else { return }
            let framed = self.frame(responseData)
            let logger = self.logger
            connection.send(content: framed, completion: .contentProcessed({ error in
                if let error = error {
                    logger.error("send_error=\(error.localizedDescription)")
                }
            }))
            self.receive(on: connection)
        }
    }

    private func frame(_ data: Data) -> Data {
        var length = UInt32(data.count)
        let lengthData = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        return lengthData + data
    }

    private func resolveIdentity(connection: NWConnection) -> ClientIdentity? {
        let endpoint = connection.endpoint
        guard case let .unix(path) = endpoint else {
            return nil
        }
        let peerPid = peerPidForSocket(path: path)
        guard peerPid > 0, let binaryPath = binaryPathForPid(peerPid) else {
            return ClientIdentity(cdhash: "unknown", binaryName: "unknown", binaryPath: "unknown")
        }
        let binaryName = URL(fileURLWithPath: binaryPath).lastPathComponent
        let cdhash = cdhashForBinary(path: binaryPath) ?? "unknown"
        return ClientIdentity(cdhash: cdhash, binaryName: binaryName, binaryPath: binaryPath)
    }

    private func peerPidForSocket(path: String) -> pid_t {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return 0
        }
        defer {
            close(fd)
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let maxLength = MemoryLayout.size(ofValue: address.sun_path) - 1
        _ = path.withCString { pointer in
            withUnsafeMutablePointer(to: &address.sun_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: maxLength) { dest in
                    strncpy(dest, pointer, maxLength)
                }
            }
        }
        let baseLength = MemoryLayout<sockaddr_un>.size
        let nameLength = path.utf8.count + 1
        let length = socklen_t(baseLength - MemoryLayout.size(ofValue: address.sun_path) + nameLength)
        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
                connect(fd, pointer, length)
            }
        }
        guard connectResult == 0 else {
            return 0
        }
        var pid = pid_t()
        var size = socklen_t(MemoryLayout<pid_t>.size)
        if getsockopt(fd, 0, LOCAL_PEERPID, &pid, &size) != 0 {
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
}
