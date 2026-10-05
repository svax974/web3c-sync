import Foundation

// MARK: - Modèles publics

public struct GroupCredentials: Sendable, Equatable {
    public let groupId: String
    public let groupKey: Data
}

public struct JoinToken: Sendable, Equatable {
    public let token: String
    /// Epoch secondes.
    public let expiresAt: Int64
}

public struct Member: Sendable, Equatable {
    public let device: String
    public let nameEnc: String?
    public let owner: Bool
    public let joinedAt: Int64
    /// Nom déchiffré avec K_name (nil si absent, illisible ou clé de groupe inconnue).
    public let name: String?
}

public struct GroupInfo: Sendable, Equatable {
    public let instance: String
    public let seq: Int64
    public let docs: Int64
    public let bytes: Int64
    public let members: Int64?
    public let purgeAt: Int64
    public let quota: [String: Int64]
}

/// Document déchiffré et vérifié.
public struct SyncDocument: Sendable, Equatable {
    public let collection: String
    public let logicalId: String
    public let docId: String
    public let payload: JSONValue
    /// `u` interne (epoch ms).
    public let updatedAt: Int64
    public let seq: Int64
    /// Horodatage de transport serveur (epoch s), 0 si inconnu.
    public let serverUpdatedAt: Int64
}

public struct Tombstone: Sendable, Equatable {
    public let collection: String
    public let docId: String
    public let seq: Int64
    /// Instant serveur de la suppression, secondes Unix (0 si inconnu).
    public let updatedAt: Int64
}

/// Élément de `changes` rejeté (déchiffrement ou vérification d'identifiant impossible).
public struct RejectedChange: Sendable, Equatable {
    public let collection: String
    public let docId: String
    public let seq: Int64
}

public struct ChangesPage: Sendable, Equatable {
    public var items: [SyncDocument]
    public var tombstones: [Tombstone]
    public var rejected: [RejectedChange]
    public var next: Int64
    public var more: Bool
}

public struct StreamEvent: Sendable, Equatable, Decodable {
    public let collection: String
    public let docId: String
    public let seq: Int64
    public let deleted: Bool
}

public struct Candidate: Sendable, Equatable {
    public var payload: JSONValue
    public var updatedAt: Int64
    public init(payload: JSONValue, updatedAt: Int64) {
        self.payload = payload
        self.updatedAt = updatedAt
    }
}

public struct UpsertResult: Sendable, Equatable {
    public let payload: JSONValue
    public let updatedAt: Int64
    public let seq: Int64
    /// false si `merge` a renvoyé nil (rien à écrire) : `seq` est alors celui du document distant.
    public let wrote: Bool
}

// MARK: - Client

public actor Web3CSyncClient {
    public nonisolated let baseURL: URL
    public nonisolated let instance: String
    public nonisolated let tlsFingerprint: String?
    public private(set) var groupId: String?
    public private(set) var groupKey: Data?

    private let deviceKey: DeviceKey
    private let adminToken: String?
    private let transport: Web3CTransport
    private var keys: DerivedKeys?
    private let basePath: String
    private let baseString: String

    public init(baseURL: URL, instance: String, deviceKey: DeviceKey, groupId: String? = nil, groupKey: Data? = nil,
                adminToken: String? = nil, tlsFingerprint: String? = nil, transport: Web3CTransport? = nil) {
        self.baseURL = baseURL
        self.instance = instance
        self.deviceKey = deviceKey
        self.groupId = groupId
        self.groupKey = groupKey
        self.keys = groupKey.map(Web3CCrypto.deriveKeys)
        self.adminToken = adminToken
        self.tlsFingerprint = tlsFingerprint
        self.transport = transport ?? URLSessionTransport(tlsFingerprint: tlsFingerprint)
        var s = baseURL.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        self.baseString = s
        var p = baseURL.path
        while p.hasSuffix("/") { p.removeLast() }
        self.basePath = p
    }

    /// Client prêt à appairer (`join`) à partir d'un lien.
    public init(link: GroupLink, deviceKey: DeviceKey, transport: Web3CTransport? = nil) throws {
        guard let url = URL(string: link.serverURL) else { throw SyncError.invalid("bad server url") }
        self.init(baseURL: url, instance: link.instance, deviceKey: deviceKey, groupId: link.groupId,
                  groupKey: link.groupKey, tlsFingerprint: link.tlsFingerprint, transport: transport)
    }

    public nonisolated var devicePublicKeyB64: String { deviceKey.publicKeyB64 }

    // MARK: Requêtes signées

    private func buildRequest(method: String, pathQuery: String, body: Data?, contentType: String?,
                              headers: [String: String] = [:], timeout: TimeInterval? = nil) throws -> URLRequest {
        guard let url = URL(string: baseString + pathQuery) else { throw SyncError.invalid("bad url") }
        let ts = String(Int64(Date().timeIntervalSince1970))
        let nonce = B64.encode(try Randomness.bytes(16))
        // Le chemin signé est celui envoyé tel quel sur le fil (préfixe éventuel de l'URL de base compris).
        let canon = Web3CCrypto.canonical(
            method: method, pathQuery: basePath + pathQuery, timestamp: ts, nonce: nonce,
            bodyHash: Web3CCrypto.bodyHash(body ?? Data()), instance: instance)
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let body = body, !body.isEmpty { req.httpBody = body }
        if let contentType = contentType { req.setValue(contentType, forHTTPHeaderField: "Content-Type") }
        req.setValue(deviceKey.publicKeyB64, forHTTPHeaderField: "X-Device")
        req.setValue(ts, forHTTPHeaderField: "X-Timestamp")
        req.setValue(nonce, forHTTPHeaderField: "X-Nonce")
        req.setValue(try Web3CCrypto.sign(deviceKey, canonical: canon), forHTTPHeaderField: "X-Signature")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let t = timeout { req.timeoutInterval = t }
        return req
    }

    @discardableResult
    private func perform(_ method: String, _ pathQuery: String, body: Data? = nil, contentType: String? = nil,
                         headers: [String: String] = [:]) async throws -> (Data, HTTPURLResponse) {
        let req = try buildRequest(method: method, pathQuery: pathQuery, body: body, contentType: contentType, headers: headers)
        let (data, resp) = try await transport.data(for: req)
        guard (200..<300).contains(resp.statusCode) else {
            throw mapHTTPError(status: resp.statusCode, body: data,
                               headers: ["x-seq": resp.value(forHTTPHeaderField: "X-Seq") ?? ""])
        }
        return (data, resp)
    }

    private func requireGroup() throws -> (gid: String, keys: DerivedKeys) {
        guard let g = groupId, let k = keys else { throw SyncError.invalid("group id/key not set") }
        return (g, k)
    }

    private func requireGroupId() throws -> String {
        guard let g = groupId else { throw SyncError.invalid("group id not set") }
        return g
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw SyncError.server(status: 200, code: "bad_response") }
    }

    // MARK: Groupes

    /// Crée le groupe. Génère `groupId`/`K_g` s'ils ne sont pas déjà définis.
    @discardableResult
    public func createGroup(deviceName: String? = nil) async throws -> GroupCredentials {
        let gid = try groupId ?? GroupLink.generateGroupId()
        let kg = try groupKey ?? GroupLink.generateGroupKey()
        var headers: [String: String] = [:]
        if let t = adminToken { headers["Authorization"] = "Bearer \(t)" }
        keys = Web3CCrypto.deriveKeys(kg)
        var obj: [String: String] = ["groupId": gid]
        if let name = deviceName {
            let aad = Web3CCrypto.aad(instance: instance, groupId: gid, collection: "_name", docId: deviceKey.publicKeyB64)
            let env = try Web3CCrypto.seal(kEnc: keys!.name, aad: aad, plaintext: Data(name.utf8))
            obj["nameEnc"] = B64.encode(env)
        }
        let body = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        try await perform("POST", "/v1/g", body: body, contentType: "application/json", headers: headers)
        groupId = gid
        groupKey = kg
        keys = Web3CCrypto.deriveKeys(kg)
        return GroupCredentials(groupId: gid, groupKey: kg)
    }

    public func createJoinToken() async throws -> JoinToken {
        let gid = try requireGroupId()
        let (d, _) = try await perform("POST", "/v1/g/\(gid)/join-tokens")
        struct R: Decodable { let token: String; let expiresAt: Int64 }
        let r = try decode(R.self, d)
        return JoinToken(token: r.token, expiresAt: r.expiresAt)
    }

    /// Lien d'appairage pour un jeton (nécessite `K_g`).
    public func makeLink(token: String) throws -> GroupLink {
        guard let g = groupId, let k = groupKey else { throw SyncError.invalid("group id/key not set") }
        return GroupLink(serverURL: baseString, instance: instance, groupId: g, token: token, groupKey: k,
                         tlsFingerprint: tlsFingerprint)
    }

    /// Appairage de cet appareil ; son nom est chiffré avec K_name (collection `_name`, docId = clé publique de l'appareil).
    public func join(token: String, deviceName: String) async throws {
        let (gid, k) = try requireGroup()
        let aad = Web3CCrypto.aad(instance: instance, groupId: gid, collection: "_name", docId: deviceKey.publicKeyB64)
        let env = try Web3CCrypto.seal(kEnc: k.name, aad: aad, plaintext: Data(deviceName.utf8))
        let obj: [String: String] = ["token": token, "nameEnc": B64.encode(env)]
        let body = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        try await perform("POST", "/v1/g/\(gid)/join", body: body, contentType: "application/json")
    }

    public func members() async throws -> [Member] {
        let gid = try requireGroupId()
        let (d, _) = try await perform("GET", "/v1/g/\(gid)/members")
        struct R: Decodable { let device: String; let nameEnc: String?; let owner: Bool; let joinedAt: Int64 }
        return try decode([R].self, d).map { r in
            Member(device: r.device, nameEnc: r.nameEnc, owner: r.owner, joinedAt: r.joinedAt,
                   name: decryptName(device: r.device, nameEnc: r.nameEnc))
        }
    }

    private func decryptName(device: String, nameEnc: String?) -> String? {
        guard let gid = groupId, let k = keys, let s = nameEnc, let env = B64.decode(s) else { return nil }
        let aad = Web3CCrypto.aad(instance: instance, groupId: gid, collection: "_name", docId: device)
        guard let pt = try? Web3CCrypto.open(kEnc: k.name, aad: aad, envelope: env) else { return nil }
        return String(data: pt, encoding: .utf8)
    }

    /// Révocation d'un appareil (propriétaire) ou départ (l'appareil lui-même).
    public func revoke(device: String) async throws {
        let gid = try requireGroupId()
        try await perform("DELETE", "/v1/g/\(gid)/members/\(device)")
    }

    public func info() async throws -> GroupInfo {
        let gid = try requireGroupId()
        let (d, _) = try await perform("GET", "/v1/g/\(gid)/info")
        struct R: Decodable {
            let instance: String; let seq: Int64; let docs: Int64; let bytes: Int64
            let members: Int64?; let purgeAt: Int64; let quota: [String: Int64]?
        }
        let r = try decode(R.self, d)
        return GroupInfo(instance: r.instance, seq: r.seq, docs: r.docs, bytes: r.bytes, members: r.members,
                         purgeAt: r.purgeAt, quota: r.quota ?? [:])
    }

    public func purgeGroup() async throws {
        let gid = try requireGroupId()
        try await perform("DELETE", "/v1/g/\(gid)")
    }

    // MARK: Documents

    private struct Plain: Codable {
        var v: Int
        var u: Int64
        var k: String
        var d: JSONValue
    }

    private static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.withoutEscapingSlashes]
        return e
    }

    /// Chiffre et écrit un document. `ifMatch` : 0 pour une création, sinon le `seq` de base. Retourne le nouveau `seq`.
    @discardableResult
    public func putDoc(collection: String, logicalId: String, payload: JSONValue, updatedAt: Int64, ifMatch: Int64) async throws -> Int64 {
        let (gid, k) = try requireGroup()
        let docId = Web3CCrypto.docId(kId: k.id, collection: collection, logicalId: logicalId)
        let plain = try Self.encoder().encode(Plain(v: 1, u: updatedAt, k: logicalId, d: payload))
        let aad = Web3CCrypto.aad(instance: instance, groupId: gid, collection: collection, docId: docId)
        let env = try Web3CCrypto.seal(kEnc: k.enc, aad: aad, plaintext: plain)
        let (d, _) = try await perform("PUT", "/v1/g/\(gid)/d/\(collection)/\(docId)", body: env,
                                       contentType: "application/octet-stream", headers: ["If-Match": String(ifMatch)])
        struct R: Decodable { let seq: Int64 }
        return try decode(R.self, d).seq
    }

    private func openDocument(collection: String, docId: String, envelope: Data, seq: Int64, serverUpdatedAt: Int64) throws -> SyncDocument {
        let (gid, k) = try requireGroup()
        let aad = Web3CCrypto.aad(instance: instance, groupId: gid, collection: collection, docId: docId)
        let pt = try Web3CCrypto.open(kEnc: k.enc, aad: aad, envelope: envelope)
        guard let p = try? JSONDecoder().decode(Plain.self, from: pt), p.v == 1 else { throw SyncError.decryption }
        guard Web3CCrypto.docId(kId: k.id, collection: collection, logicalId: p.k) == docId else { throw SyncError.integrity }
        return SyncDocument(collection: collection, logicalId: p.k, docId: docId, payload: p.d, updatedAt: p.u,
                            seq: seq, serverUpdatedAt: serverUpdatedAt)
    }

    /// Lit, déchiffre et vérifie un document. 404 -> `.notFound` ; supprimé -> `.gone(seq:)`.
    public func getDoc(collection: String, logicalId: String) async throws -> SyncDocument {
        let (gid, k) = try requireGroup()
        let docId = Web3CCrypto.docId(kId: k.id, collection: collection, logicalId: logicalId)
        let (d, r) = try await perform("GET", "/v1/g/\(gid)/d/\(collection)/\(docId)")
        let seq = Int64(r.value(forHTTPHeaderField: "X-Seq") ?? "") ?? 0
        let upd = Int64(r.value(forHTTPHeaderField: "X-Updated-At") ?? "") ?? 0
        let doc = try openDocument(collection: collection, docId: docId, envelope: d, seq: seq, serverUpdatedAt: upd)
        guard doc.logicalId == logicalId else { throw SyncError.integrity }
        return doc
    }

    /// Supprime (tombstone). Retourne le nouveau `seq`.
    @discardableResult
    public func deleteDoc(collection: String, logicalId: String, ifMatch: Int64) async throws -> Int64 {
        let (gid, k) = try requireGroup()
        let docId = Web3CCrypto.docId(kId: k.id, collection: collection, logicalId: logicalId)
        let (d, _) = try await perform("DELETE", "/v1/g/\(gid)/d/\(collection)/\(docId)", headers: ["If-Match": String(ifMatch)])
        struct R: Decodable { let seq: Int64 }
        return try decode(R.self, d).seq
    }

    /// Une page de `changes`. Les éléments illisibles sont listés dans `rejected` (le curseur avance quand même).
    public func changes(since: Int64, limit: Int? = nil) async throws -> ChangesPage {
        let gid = try requireGroupId()
        var q = "/v1/g/\(gid)/changes?since=\(since)"
        if let l = limit { q += "&limit=\(l)" }
        let (d, _) = try await perform("GET", q)
        struct Item: Decodable {
            let collection: String; let docId: String; let seq: Int64
            let deleted: Bool; let updatedAt: Int64?; let env: String?
        }
        struct R: Decodable { let items: [Item]; let next: Int64; let more: Bool }
        let r = try decode(R.self, d)
        var page = ChangesPage(items: [], tombstones: [], rejected: [], next: r.next, more: r.more)
        for it in r.items {
            if it.deleted {
                page.tombstones.append(Tombstone(collection: it.collection, docId: it.docId, seq: it.seq, updatedAt: it.updatedAt ?? 0))
                continue
            }
            if let s = it.env, let env = B64.decode(s),
               let doc = try? openDocument(collection: it.collection, docId: it.docId, envelope: env,
                                           seq: it.seq, serverUpdatedAt: it.updatedAt ?? 0) {
                page.items.append(doc)
            } else {
                page.rejected.append(RejectedChange(collection: it.collection, docId: it.docId, seq: it.seq))
            }
        }
        return page
    }

    /// Pagination complète depuis `since`.
    public func changesAll(since: Int64 = 0, pageSize: Int? = nil) async throws -> ChangesPage {
        var all = ChangesPage(items: [], tombstones: [], rejected: [], next: since, more: false)
        var cursor = since
        while true {
            let p = try await changes(since: cursor, limit: pageSize)
            all.items += p.items
            all.tombstones += p.tombstones
            all.rejected += p.rejected
            all.next = p.next
            if !p.more || p.next <= cursor { break }
            cursor = p.next
        }
        return all
    }

    // MARK: Upsert

    /// Boucle GET / fusion / PUT avec If-Match. `merge` reçoit l'état distant (nil si absent ou supprimé) et renvoie
    /// ce qu'il faut écrire (nil = ne rien écrire). Sur 409, relit et recommence, `maxAttempts` fois au plus.
    public func upsert(collection: String, logicalId: String, maxAttempts: Int = 6,
                       merge: @Sendable (SyncDocument?) async throws -> Candidate?) async throws -> UpsertResult {
        var lastConflict: SyncError = .conflict(seq: -1)
        for _ in 0..<max(1, maxAttempts) {
            var remote: SyncDocument?
            var base: Int64 = 0
            do {
                let doc = try await getDoc(collection: collection, logicalId: logicalId)
                remote = doc
                base = doc.seq
            } catch SyncError.notFound {
                base = 0
            } catch SyncError.gone(let seq) {
                base = max(seq, 0)
            }
            guard let cand = try await merge(remote) else {
                guard let r = remote else { throw SyncError.notFound }
                return UpsertResult(payload: r.payload, updatedAt: r.updatedAt, seq: r.seq, wrote: false)
            }
            do {
                let seq = try await putDoc(collection: collection, logicalId: logicalId, payload: cand.payload,
                                           updatedAt: cand.updatedAt, ifMatch: base)
                return UpsertResult(payload: cand.payload, updatedAt: cand.updatedAt, seq: seq, wrote: true)
            } catch let e as SyncError {
                guard case .conflict = e else { throw e }
                lastConflict = e
            }
        }
        throw lastConflict
    }

    /// Variante avec valeur locale : le `u` interne le plus récent gagne (égalité : l'état distant est conservé).
    public func upsert(collection: String, logicalId: String, local: Candidate, maxAttempts: Int = 6,
                       merge: (@Sendable (_ local: Candidate, _ remote: SyncDocument) -> Candidate)? = nil) async throws -> UpsertResult {
        try await upsert(collection: collection, logicalId: logicalId, maxAttempts: maxAttempts) { remote in
            guard let remote = remote else { return local }
            if let merge = merge { return merge(local, remote) }
            if local.updatedAt > remote.updatedAt { return local }
            return nil
        }
    }

    // MARK: SSE

    /// Flux d'événements `change` avec reconnexion (backoff exponentiel) et reprise par `since`. Se termine par
    /// une erreur sur 401/403/404/400, sinon continue jusqu'à l'annulation de la tâche consommatrice.
    public nonisolated func stream(since: Int64 = 0, initialBackoff: TimeInterval = 1, maxBackoff: TimeInterval = 30)
        -> AsyncThrowingStream<StreamEvent, Error> {
        AsyncThrowingStream { cont in
            let task = Task {
                var last = since
                var delay = initialBackoff
                while !Task.isCancelled {
                    do {
                        let (resp, lines) = try await self.openStream(since: last)
                        guard resp.statusCode == 200 else { throw mapHTTPError(status: resp.statusCode, body: nil) }
                        delay = initialBackoff
                        var data = ""
                        for try await line in lines {
                            if line.isEmpty {
                                if !data.isEmpty, let ev = try? JSONDecoder().decode(StreamEvent.self, from: Data(data.utf8)) {
                                    last = max(last, ev.seq)
                                    cont.yield(ev)
                                }
                                data = ""
                            } else if line.hasPrefix("data:") {
                                var v = line.dropFirst(5)
                                if v.hasPrefix(" ") { v = v.dropFirst() }
                                data += (data.isEmpty ? "" : "\n") + v
                            }
                            // `id:`, `event:` et commentaires (`: ping`) sont ignorés : le curseur vient des données.
                        }
                    } catch is CancellationError {
                        break
                    } catch let e as SyncError {
                        switch e {
                        case .unauthorized, .forbidden, .notFound, .badRequest, .invalid:
                            cont.finish(throwing: e)
                            return
                        default: break
                        }
                    } catch {
                        // erreur réseau transitoire : reconnexion
                    }
                    if Task.isCancelled { break }
                    try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                    delay = min(delay * 2, maxBackoff)
                }
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    private func openStream(since: Int64) async throws -> (HTTPURLResponse, AsyncThrowingStream<String, Error>) {
        let gid = try requireGroupId()
        let req = try buildRequest(method: "GET", pathQuery: "/v1/g/\(gid)/stream?since=\(since)", body: nil,
                                   contentType: nil, headers: ["Accept": "text/event-stream"], timeout: 90)
        return try await transport.lines(for: req)
    }

    // MARK: Blobs

    public func putBlob(id: String, data: Data) async throws {
        let gid = try requireGroupId()
        try await perform("PUT", "/v1/g/\(gid)/b/\(id)", body: data, contentType: "application/octet-stream")
    }

    /// Lit un blob (ou une plage d'octets, bornes incluses).
    public func getBlob(id: String, range: ClosedRange<Int>? = nil) async throws -> Data {
        let gid = try requireGroupId()
        var h: [String: String] = [:]
        if let r = range { h["Range"] = "bytes=\(r.lowerBound)-\(r.upperBound)" }
        return try await perform("GET", "/v1/g/\(gid)/b/\(id)", headers: h).0
    }

    public func deleteBlob(id: String) async throws {
        let gid = try requireGroupId()
        try await perform("DELETE", "/v1/g/\(gid)/b/\(id)")
    }
}
