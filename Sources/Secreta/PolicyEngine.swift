import Foundation

final class PolicyEngine {
    private var metadataStore: [String: StoredSecretMetadata] = [:]
    private let queue = DispatchQueue(label: "secreta.policy")

    func recordSecret(name: String, metadata: StoredSecretMetadata) {
        queue.sync {
            metadataStore[name] = metadata
        }
    }

    func metadata(for name: String) -> StoredSecretMetadata? {
        return queue.sync {
            metadataStore[name]
        }
    }

    func recordAccess(name: String) {
        queue.sync {
            if var meta = metadataStore[name] {
                meta.lastAccessAt = Date()
                metadataStore[name] = meta
            }
        }
    }

    func resolveClientIdentity() -> ClientIdentity {
        return ClientIdentity(cdhash: "unknown", binaryName: "unknown", binaryPath: "unknown")
    }
}
