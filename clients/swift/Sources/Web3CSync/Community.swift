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
    private let configError: SyncError?
    private let clock: @Sendable () -> Date

    /// `clock` : horloge injectable (instant `t` des votes). `http://` refusé hors loopback ; empreinte TLS non vide
    /// mais invalide : toute requête échoue (`SyncError.invalid`).
    public init(baseURL: URL, powBits: Int = 16, tlsFingerprint: String? = nil, transport: Web3CTransport? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.baseURL = baseURL
        self.powBits = powBits
        self.clock = clock
        self.configError = validateEndpoint(baseURL, tlsFingerprint: tlsFingerprint)
        self.transport = transport ?? URLSessionTransport(tlsFingerprint: tlsFingerprint)
        var s = baseURL.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        baseString = s
    }

    private func request(_ method: String, _ path: String, body: Data? = nil) throws -> URLRequest {
        if let e = configError { throw e }
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

    /// `^(movie|tv|series):tmdb:[0-9]{1,9}$`
    static func validVoteKey(_ k: String) -> Bool {
        let parts = k.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, ["movie", "tv", "series"].contains(String(parts[0])), parts[1] == "tmdb" else { return false }
        let id = parts[2].utf8
        return (1...9).contains(id.count) && id.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    /// Vote (`rating` nil = retrait). `kUser` : `K_rating` du groupe du profil (`DerivedKeys.rating`), sinon clé locale
    /// aléatoire de l'appareil. Le corps porte `t` (secondes, horloge injectée), lié à la preuve de travail : le serveur
    /// refuse (409 -> `SyncError.conflict`) un vote dont `t` n'est pas strictement postérieur au précédent du même
    /// pseudonyme, et (400) un `t` à plus de 10 min de son horloge.
    public func vote(contentKey: String, profileId: String, kUser: Data, rating: Double?) async throws {
        guard Self.validVoteKey(contentKey) else { throw SyncError.invalid("bad content key") }
        if let r = rating, !r.isFinite { throw SyncError.invalid("bad rating") }
        let p = Web3CCrypto.pseudonym(kUser: kUser, profileId: profileId, contentKey: contentKey)
        let t = Int64(clock().timeIntervalSince1970)
        let n = try await Web3CCrypto.solvePowAsync(contentKey: contentKey, pseudonym: p, rating: rating, t: t, powBits: powBits)
        let body = Data("{\"p\":\"\(p)\",\"r\":\(Web3CCrypto.ratingText(rating)),\"t\":\(t),\"n\":\(n)}".utf8)
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
