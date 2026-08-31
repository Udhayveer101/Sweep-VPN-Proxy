import Foundation
import CryptoKit

/// Per-network memory ("this café blocks UDP; TLS worked here") persisted
/// on-device only, keyed by an HMAC fingerprint so the store never reveals
/// which networks the user has been on.
public struct NetworkMemoryStore: Sendable {
    private static let key = "network.memory.v1"
    private let store: SecretStore

    public init(store: SecretStore) { self.store = store }

    public func all() -> [String: NetworkMemory] {
        guard let data = (try? store.get(Self.key)) ?? nil else { return [:] }
        return (try? IPCCodec.decode([String: NetworkMemory].self, data)) ?? [:]
    }

    public func memory(for fingerprint: String) -> NetworkMemory {
        all()[fingerprint] ?? NetworkMemory()
    }

    public func update(_ fingerprint: String, _ mutate: (inout NetworkMemory) -> Void) {
        var everything = all()
        var entry = everything[fingerprint] ?? NetworkMemory()
        mutate(&entry)
        everything[fingerprint] = entry
        // Bound the store: a device that roams a lot must not grow forever.
        if everything.count > 64 {
            let keep = everything.sorted { ($0.value.lastSeen ?? .distantPast) > ($1.value.lastSeen ?? .distantPast) }
                .prefix(64)
            everything = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
        if let data = try? IPCCodec.encode(everything) { try? store.set(data, for: Self.key) }
    }

    public func forget() { try? store.remove(Self.key) }
}
