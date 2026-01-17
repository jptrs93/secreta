import Foundation

final class CacheManager {
    private var cache: [String: CachedAccessRecord] = [:]
    private let queue = DispatchQueue(label: "secreta.cache")

    func hasValidCache(for clientCdhash: String, secretName: String) -> Bool {
        let key = cacheKey(clientCdhash: clientCdhash, secretName: secretName)
        return queue.sync {
            guard let record = cache[key] else {
                return false
            }
            return record.expiresAt > Date()
        }
    }

    func storeCache(for clientCdhash: String, secretName: String, cacheSeconds: Int) {
        guard cacheSeconds > 0 else {
            return
        }
        let key = cacheKey(clientCdhash: clientCdhash, secretName: secretName)
        let record = CachedAccessRecord(clientCdhash: clientCdhash, secretName: secretName, expiresAt: Date().addingTimeInterval(TimeInterval(cacheSeconds)))
        queue.sync {
            cache[key] = record
        }
    }

    private func cacheKey(clientCdhash: String, secretName: String) -> String {
        return "\(clientCdhash)::\(secretName)"
    }
}
