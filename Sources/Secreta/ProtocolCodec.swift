import Foundation

enum ProtocolCodecError: Error {
    case invalidEnvelope
    case invalidPayload
}

struct ProtocolCodec {
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    init() {
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
    }

    func decodeEnvelope(from data: Data) throws -> RequestEnvelope {
        guard let envelope = try? decoder.decode(RequestEnvelope.self, from: data) else {
            throw ProtocolCodecError.invalidEnvelope
        }
        return envelope
    }

    func decodeResponseEnvelope(from data: Data) throws -> ResponseEnvelope {
        guard let envelope = try? decoder.decode(ResponseEnvelope.self, from: data) else {
            throw ProtocolCodecError.invalidEnvelope
        }
        return envelope
    }

    func encodeEnvelope(_ envelope: ResponseEnvelope) throws -> Data {
        return try encoder.encode(envelope)
    }

    func encodeRequestEnvelope(_ envelope: RequestEnvelope) throws -> Data {
        return try encoder.encode(envelope)
    }

    func decodeParams<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard let params = try? decoder.decode(T.self, from: data) else {
            throw ProtocolCodecError.invalidPayload
        }
        return params
    }

    func encodeResult<T: Encodable>(_ result: T) throws -> Data {
        return try encoder.encode(result)
    }
}
