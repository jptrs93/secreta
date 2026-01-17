import Foundation

protocol RequestHandler {
    func handle(payload: Data, completion: @escaping (Data) -> Void)
}

final class SecretRequestRouter: RequestHandler {
    private let codec = ProtocolCodec()
    private let service: SecretService
    private let logger = LoggerFactory.make("router")

    init(service: SecretService) {
        self.service = service
    }

    func handle(payload: Data, completion: @escaping (Data) -> Void) {
        do {
            let envelope = try codec.decodeEnvelope(from: payload)
            switch envelope.method {
            case "secret.create":
                let request = try codec.decodeParams(SecretCreateRequest.self, from: envelope.params)
                handleCreate(request: request, envelope: envelope, completion: completion)
            case "secret.access":
                let request = try codec.decodeParams(SecretAccessRequest.self, from: envelope.params)
                handleAccess(request: request, envelope: envelope, completion: completion)
            case "secret.meta":
                let request = try codec.decodeParams(SecretAccessRequest.self, from: envelope.params)
                handleMeta(request: request, envelope: envelope, completion: completion)
            case "secret.delete":
                let request = try codec.decodeParams(SecretDeleteRequest.self, from: envelope.params)
                handleDelete(request: request, envelope: envelope, completion: completion)
            case "health.ping":
                handleHealth(envelope: envelope, completion: completion)
            default:
                completion(errorEnvelope(for: envelope.requestId, code: "invalid_request", message: "Unknown method"))
            }
        } catch {
            logger.error("decode_error=\(error.localizedDescription)")
            completion(errorEnvelope(for: UUID(), code: "invalid_request", message: "Malformed request"))
        }
    }

    private func handleCreate(request: SecretCreateRequest, envelope: RequestEnvelope, completion: @escaping (Data) -> Void) {
        let response = service.createSecret(request: request)
        completion(encodeResult(response, requestId: envelope.requestId))
    }

    private func handleAccess(request: SecretAccessRequest, envelope: RequestEnvelope, completion: @escaping (Data) -> Void) {
        let response = service.accessSecret(request: request)
        switch response {
        case .success(let value):
            completion(encodeResult(value, requestId: envelope.requestId))
        case .failure(let error):
            completion(errorEnvelope(for: envelope.requestId, code: error.code, message: error.message))
        }
    }

    private func handleMeta(request: SecretAccessRequest, envelope: RequestEnvelope, completion: @escaping (Data) -> Void) {
        let response = service.secretMeta(name: request.name)
        switch response {
        case .success(let meta):
            completion(encodeResult(meta, requestId: envelope.requestId))
        case .failure(let error):
            completion(errorEnvelope(for: envelope.requestId, code: error.code, message: error.message))
        }
    }

    private func handleDelete(request: SecretDeleteRequest, envelope: RequestEnvelope, completion: @escaping (Data) -> Void) {
        let response = service.deleteSecret(name: request.name)
        switch response {
        case .success(let result):
            completion(encodeResult(result, requestId: envelope.requestId))
        case .failure(let error):
            completion(errorEnvelope(for: envelope.requestId, code: error.code, message: error.message))
        }
    }

    private func handleHealth(envelope: RequestEnvelope, completion: @escaping (Data) -> Void) {
        let response = service.healthStatus()
        completion(encodeResult(response, requestId: envelope.requestId))
    }

    private func encodeResult<T: Encodable>(_ result: T, requestId: UUID) -> Data {
        do {
            let payload = try codec.encodeResult(result)
            let envelope = ResponseEnvelope(requestId: requestId, result: payload, error: nil)
            return try codec.encodeEnvelope(envelope)
        } catch {
            return errorEnvelope(for: requestId, code: "internal", message: "Encoding error")
        }
    }

    private func errorEnvelope(for requestId: UUID, code: String, message: String) -> Data {
        let error = ErrorEnvelope(code: code, message: message, retryable: false, details: nil)
        let envelope = ResponseEnvelope(requestId: requestId, result: nil, error: error)
        return (try? codec.encodeEnvelope(envelope)) ?? Data()
    }
}

struct ServiceError: Error {
    let code: String
    let message: String
}
