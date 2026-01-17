import Foundation
import Network

final class SocketServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "secreta.socket")
    private let logger = LoggerFactory.make("socket")
    private let handler: RequestHandler

    init(socketPath: String, handler: RequestHandler) throws {
        self.handler = handler
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
}
