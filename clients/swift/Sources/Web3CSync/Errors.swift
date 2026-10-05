import Foundation

/// Erreurs typées du client web3c-sync.
public enum SyncError: Error, Equatable, Sendable {
    /// 409 : `seq` courant du document côté serveur.
    case conflict(seq: Int64)
    /// 413 / 429 `quota`.
    case quota
    case tooLarge
    case rateLimited
    case unauthorized
    case forbidden
    case notFound
    /// 410 : document supprimé (`seq` du tombstone, à passer en If-Match pour recréer).
    case gone(seq: Int64)
    case badRequest
    /// 5xx ou statut inattendu.
    case server(status: Int, code: String?)
    /// Enveloppe illisible (mauvaise clé, altération, mauvais contexte AAD). Cause volontairement non précisée.
    case decryption
    /// Document déchiffré mais `HMAC(K_id, collection, k) != docId` reçu.
    case integrity
    case invalid(String)
    /// Retour en arrière détecté : curseur `changes` qui diminue, ou compteur `c` d'un document inférieur au plancher
    /// connu (`counterFloor`). Seul un serveur malveillant ou défaillant peut le provoquer.
    case rollback
    /// Document déchiffré sans compteur `c` entier >= 1 (protocole révisé, pas de compatibilité ascendante).
    case missingCounter
    case transport(String)
}

struct APIErrorBody: Decodable {
    var error: String?
    var seq: Int64?
    var limit: String?
}

func mapHTTPError(status: Int, body: Data?, headers: [String: String] = [:]) -> SyncError {
    let b = body.flatMap { try? JSONDecoder().decode(APIErrorBody.self, from: $0) }
    switch status {
    case 400: return .badRequest
    case 401: return .unauthorized
    case 403: return .forbidden
    case 404: return .notFound
    case 409: return .conflict(seq: b?.seq ?? -1)
    case 410: return .gone(seq: Int64(headers["x-seq"] ?? "") ?? -1)
    case 413: return .tooLarge
    case 429: return b?.error == "quota" ? .quota : .rateLimited
    default: return .server(status: status, code: b?.error)
    }
}
