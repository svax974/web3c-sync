import Foundation
import CryptoKit

/// Clé d'appareil Ed25519. La graine (32 octets) est exportable pour être stockée dans un coffre.
public struct DeviceKey: Sendable {
    private let key: Curve25519.Signing.PrivateKey

    public init() { key = Curve25519.Signing.PrivateKey() }

    public init(seed: Data) throws {
        guard seed.count == 32 else { throw SyncError.invalid("seed must be 32 bytes") }
        do { key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed) } catch { throw SyncError.invalid("bad seed") }
    }

    public var seed: Data { key.rawRepresentation }
    public var publicKey: Data { key.publicKey.rawRepresentation }
    public var publicKeyB64: String { B64.encode(publicKey) }

    public func sign(_ message: Data) throws -> Data {
        do { return try key.signature(for: message) } catch { throw SyncError.invalid("signature failure") }
    }
}

/// Coffre de la clé d'appareil. L'implémentation Keychain est fournie par l'application.
public protocol DeviceKeyStore: Sendable {
    func load() throws -> DeviceKey?
    func save(_ key: DeviceKey) throws
    func delete() throws
}

public extension DeviceKeyStore {
    /// Charge la clé existante ou en génère puis enregistre une nouvelle.
    func loadOrCreate() throws -> DeviceKey {
        if let k = try load() { return k }
        let k = DeviceKey()
        try save(k)
        return k
    }
}

/// Implémentation mémoire (tests).
public final class MemoryDeviceKeyStore: DeviceKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var key: DeviceKey?

    public init(key: DeviceKey? = nil) { self.key = key }

    public func load() throws -> DeviceKey? { lock.lock(); defer { lock.unlock() }; return key }
    public func save(_ key: DeviceKey) throws { lock.lock(); defer { lock.unlock() }; self.key = key }
    public func delete() throws { lock.lock(); defer { lock.unlock() }; key = nil }
}
