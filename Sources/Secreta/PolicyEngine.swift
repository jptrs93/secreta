import Foundation

final class PolicyEngine: ClientIdentitySink {
    private var metadataStore: [String: StoredSecretMetadata] = [:]
    private var currentIdentity = ClientIdentity(cdhash: "unknown", binaryName: "unknown", binaryPath: "unknown")
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
        return queue.sync { currentIdentity }
    }

    func updateClientIdentity(_ identity: ClientIdentity) {
        queue.sync {
            currentIdentity = identity
        }
    }

    func removeSecret(name: String) {
        _ = queue.sync {
            metadataStore.removeValue(forKey: name)
        }
    }
}
