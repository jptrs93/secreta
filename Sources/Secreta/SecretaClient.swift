import Foundation
import Darwin

final class SecretaClient {
    private let socketPath: String
    private let timeout: TimeInterval
    private let codec = ProtocolCodec()

    init(socketPath: String, timeout: TimeInterval) {
        self.socketPath = socketPath
        self.timeout = timeout
    }

    func createSecret(name: String, secretValue: String, cacheSeconds: Int?) throws -> SecretCreateResponse {
        let request = SecretCreateRequest(
            name: name,
            secretValue: secretValue,
            cacheSeconds: cacheSeconds,
            metadata: nil
        )
        return try send(method: "secret.create", params: request, responseType: SecretCreateResponse.self)
    }

    func createRawSecret(name: String, secretValue: String) throws -> SecretCreateResponse {
        return try createSecret(name: name, secretValue: secretValue, cacheSeconds: 0)
    }

    func fetchRawSecret(name: String, reason: String?) throws -> SecretAccessResponse {
        let request = SecretAccessRequest(name: name, reason: reason)
        return try send(method: "secret.access", params: request, responseType: SecretAccessResponse.self)
    }

    func fetchSecret(name: String, reason: String?) throws -> SecretAccessResponse {
        let request = SecretAccessRequest(name: name, reason: reason)
        return try send(method: "secret.access", params: request, responseType: SecretAccessResponse.self)
    }

    func deleteSecret(name: String) throws -> SecretDeleteResponse {
        let request = SecretDeleteRequest(name: name)
        return try send(method: "secret.delete", params: request, responseType: SecretDeleteResponse.self)
    }

    func healthStatus() throws -> HealthResponse {
        return try send(method: "health.ping", params: EmptyParams(), responseType: HealthResponse.self)
    }

    private func send<P: Encodable, R: Decodable>(method: String, params: P, responseType: R.Type) throws -> R {
        let requestId = UUID()
        let paramsData = try codec.encodeResult(params)
        let envelope = RequestEnvelope(requestId: requestId, method: method, params: paramsData)
        let payload = try codec.encodeRequestEnvelope(envelope)
        let framed = frame(payload)

        let fileDescriptor = try openSocket()
        defer {
            close(fileDescriptor)
        }

        try writeFully(fileDescriptor, data: framed)
        let responseData = try readFrame(fileDescriptor)
        let responseEnvelope = try codec.decodeResponseEnvelope(from: responseData)

        if let error = responseEnvelope.error {
            throw ClientError.remoteError(code: error.code, message: error.message)
        }
        guard let result = responseEnvelope.result else {
            throw ClientError.emptyResponse
        }
        return try codec.decodeParams(responseType, from: result)
    }

    private func openSocket() throws -> Int32 {
        let fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fileDescriptor >= 0 else {
            throw ClientError.socketFailure
        }

        if timeout > 0 {
            var timeoutValue = timeval(tv_sec: Int(timeout), tv_usec: 0)
            setsockopt(fileDescriptor, SOL_SOCKET, SO_RCVTIMEO, &timeoutValue, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fileDescriptor, SOL_SOCKET, SO_SNDTIMEO, &timeoutValue, socklen_t(MemoryLayout<timeval>.size))
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let maxLength = MemoryLayout.size(ofValue: address.sun_path) - 1
        let pathData = socketPath.utf8
        guard pathData.count <= maxLength else {
            close(fileDescriptor)
            throw ClientError.invalidSocketPath
        }
        withUnsafeMutablePointer(to: &address.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: maxLength) { pointer in
                _ = socketPath.withCString { stringPointer in
                    strncpy(pointer, stringPointer, maxLength)
                }
            }
        }

        let baseLength = MemoryLayout<sockaddr_un>.size
        let nameLength = socketPath.utf8.count + 1
        let length = socklen_t(baseLength - MemoryLayout.size(ofValue: address.sun_path) + nameLength)
        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
                connect(fileDescriptor, pointer, length)
            }
        }
        guard connectResult == 0 else {
            close(fileDescriptor)
            throw ClientError.connectionFailure
        }

        return fileDescriptor
    }

    private func frame(_ data: Data) -> Data {
        var length = UInt32(data.count).littleEndian
        let lengthData = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        return lengthData + data
    }

    private func readFrame(_ fileDescriptor: Int32) throws -> Data {
        let header = try readFully(fileDescriptor, length: 4)
        guard header.count == 4 else {
            throw ClientError.emptyResponse
        }

        let length = header.withUnsafeBytes { $0.load(as: UInt32.self) }
        let payloadLength = Int(UInt32(littleEndian: length))
        guard payloadLength > 0 else {
            throw ClientError.emptyResponse
        }
        return try readFully(fileDescriptor, length: payloadLength)
    }

    private func readFully(_ fileDescriptor: Int32, length: Int) throws -> Data {
        var data = Data()
        data.reserveCapacity(length)

        var buffer = [UInt8](repeating: 0, count: min(4096, length))
        var remaining = length

        while remaining > 0 {
            let chunkSize = min(remaining, buffer.count)
            let readCount = buffer.withUnsafeMutableBytes { pointer in
                read(fileDescriptor, pointer.baseAddress, chunkSize)
            }
            if readCount < 0 {
                throw ClientError.readFailure
            }
            if readCount == 0 {
                throw ClientError.readFailure
            }
            data.append(buffer, count: readCount)
            remaining -= readCount
        }

        return data
    }

    private func writeFully(_ fileDescriptor: Int32, data: Data) throws {
        var offset = 0
        let total = data.count
        try data.withUnsafeBytes { pointer in
            while offset < total {
                let writeCount = write(fileDescriptor, pointer.baseAddress?.advanced(by: offset), total - offset)
                if writeCount < 0 {
                    throw ClientError.writeFailure
                }
                offset += writeCount
            }
        }
    }
}

enum ClientError: Error {
    case connectionFailure
    case emptyResponse
    case invalidSocketPath
    case readFailure
    case remoteError(code: String, message: String)
    case socketFailure
    case writeFailure
}
