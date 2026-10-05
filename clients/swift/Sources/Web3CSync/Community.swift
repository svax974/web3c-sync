import Foundation

public struct RatingAggregate: Sendable, Equatable, Decodable {
    public let count: Int
    public let sum: Double
    public let avg: Double
}

/// Notes communautaires (§9) : routes publiques, sans signature d'appareil.
public final class CommunityClient: Sendable {
    public let baseURL: URL
    public let powBits: Int
    private let transport: Web3CTransport
    private let baseString: String

    public init(baseURL: URL, powBits: Int = 16, tlsFingerprint: String? = nil, transport: Web3CTransport? = nil) {
        self.baseURL = baseURL
        self.powBits = powBits
        self.transport = transport ?? URLSessionTransport(tlsFingerprint: tlsFingerprint)
        var s = baseURL.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        baseString = s
    }

    private func request(_ method: String, _ path: String, body: Data? = nil) throws -> URLRequest {
        guard let url = URL(string: baseString + path) else { throw SyncError.invalid("bad url") }
        var r = URLRequest(url: url)
        r.httpMethod = method
        if let b = body {
            r.httpBody = b
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return r
    }

    private func run(_ req: URLRequest) async throws -> Data {
        let (d, resp) = try await transport.data(for: req)
        guard (200..<300).contains(resp.statusCode) else { throw mapHTTPError(status: resp.statusCode, body: d) }
        return d
    }

    static func validKey(_ k: String) -> Bool {
        let n = k.utf8.count
        return n >= 1 && n <= 128 && k.utf8.allSatisfy {
            ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x3A || $0 == 0x5F || $0 == 0x2E || $0 == 0x2D
        }
    }

    /// Vote (`rating` nil = retrait). `kUser` : K_id du groupe du profil, sinon clé locale aléatoire de l'appareil.
    public func vote(contentKey: String, profileId: String, kUser: Data, rating: Double?) async throws {
        guard Self.validKey(contentKey) else { throw SyncError.invalid("bad content key") }
        if let r = rating, !r.isFinite { throw SyncError.invalid("bad rating") }
        let p = Web3CCrypto.pseudonym(kUser: kUser, profileId: profileId, contentKey: contentKey)
        let n = try await Web3CCrypto.solvePowAsync(contentKey: contentKey, pseudonym: p, rating: rating, powBits: powBits)
        let body = Data("{\"p\":\"\(p)\",\"r\":\(Web3CCrypto.ratingText(rating)),\"n\":\(n)}".utf8)
        _ = try await run(try request("PUT", "/v1/public/ratings/\(contentKey)", body: body))
    }

    public func get(contentKey: String) async throws -> RatingAggregate {
        guard Self.validKey(contentKey) else { throw SyncError.invalid("bad content key") }
        let d = try await run(try request("GET", "/v1/public/ratings/\(contentKey)"))
        do { return try JSONDecoder().decode(RatingAggregate.self, from: d) }
        catch { throw SyncError.server(status: 200, code: "bad_response") }
    }

    /// Jusqu'à 100 clés par appel.
    public func query(contentKeys: [String]) async throws -> [String: RatingAggregate] {
        guard !contentKeys.isEmpty, contentKeys.count <= 100, contentKeys.allSatisfy(Self.validKey) else {
            throw SyncError.invalid("1...100 valid keys required")
        }
        let body = try JSONSerialization.data(withJSONObject: ["keys": contentKeys])
        let d = try await run(try request("POST", "/v1/public/ratings/query", body: body))
        struct R: Decodable { let items: [String: RatingAggregate] }
        do { return try JSONDecoder().decode(R.self, from: d).items }
        catch { throw SyncError.server(status: 200, code: "bad_response") }
    }
}
