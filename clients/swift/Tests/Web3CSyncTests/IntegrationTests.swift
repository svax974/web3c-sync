import XCTest
import Darwin
@testable import Web3CSync

/// Lance le vrai serveur Go (variable d'environnement WEB3C_SYNCD = chemin du binaire).
final class IntegrationTests: XCTestCase {
    var process: Process?
    var tmp: URL!
    var base: URL!
    let instance = "iptv"

    override func setUp() async throws {
        guard let bin = ProcessInfo.processInfo.environment["WEB3C_SYNCD"], !bin.isEmpty else {
            throw XCTSkip("WEB3C_SYNCD non défini : tests d'intégration sautés")
        }
        tmp = FileManager.default.temporaryDirectory.appendingPathComponent("web3c-sync-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let port = try Self.freePort()
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        var env = ProcessInfo.processInfo.environment
        env["SYNC_INSTANCE"] = instance
        env["SYNC_LISTEN"] = "127.0.0.1:\(port)"
        env["SYNC_DB"] = tmp.appendingPathComponent("s.db").path
        env["SYNC_BLOB_DIR"] = tmp.appendingPathComponent("b").path
        env["SYNC_POW_BITS"] = "8"
        p.environment = env
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        process = p
        base = URL(string: "http://127.0.0.1:\(port)")!
        // attente de /v1/health
        var ok = false
        for _ in 0..<100 {
            if let (_, r) = try? await URLSession.shared.data(from: base.appendingPathComponent("v1/health")),
               (r as? HTTPURLResponse)?.statusCode == 200 { ok = true; break }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTAssertTrue(ok, "serveur non démarré")
    }

    override func tearDown() async throws {
        process?.terminate()
        process?.waitUntilExit()
        if let t = tmp { try? FileManager.default.removeItem(at: t) }
    }

    static func freePort() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard r == 0 else { throw SyncError.transport("bind") }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return Int(UInt16(bigEndian: addr.sin_port))
    }

    func newClient(_ key: DeviceKey = DeviceKey(), gid: String? = nil, kg: Data? = nil) -> Web3CSyncClient {
        Web3CSyncClient(baseURL: base, instance: instance, deviceKey: key, groupId: gid, groupKey: kg)
    }

    /// Propriétaire + second appareil appairés par lien.
    func pair() async throws -> (owner: Web3CSyncClient, other: Web3CSyncClient, otherKey: DeviceKey) {
        let owner = newClient()
        try await owner.createGroup()
        let tok = try await owner.createJoinToken()
        let text = try await owner.makeLink(token: tok.token).format()
        let link = try GroupLink.parse(text)
        let otherKey = DeviceKey()
        let other = try Web3CSyncClient(link: link, deviceKey: otherKey)
        try await other.join(token: link.token, deviceName: "Salon Apple TV")
        return (owner, other, otherKey)
    }

    func testPairingAndEncryptedExchange() async throws {
        let (owner, other, otherKey) = try await pair()
        let members = try await owner.members()
        XCTAssertEqual(members.count, 2)
        XCTAssertEqual(members.first { $0.device == otherKey.publicKeyB64 }?.name, "Salon Apple TV")
        XCTAssertEqual(members.filter(\.owner).count, 1)

        let seq = try await owner.putDoc(collection: "progress", logicalId: "movie_1", payload: ["pos": 120, "dur": 5400], updatedAt: 1000, ifMatch: 0)
        XCTAssertEqual(seq, 1)
        let doc = try await other.getDoc(collection: "progress", logicalId: "movie_1")
        XCTAssertEqual(doc.payload, ["pos": 120, "dur": 5400])
        XCTAssertEqual(doc.updatedAt, 1000)
        XCTAssertEqual(doc.logicalId, "movie_1")
        XCTAssertEqual(doc.seq, 1)

        let info = try await other.info()
        XCTAssertEqual(info.instance, "iptv")
        XCTAssertEqual(info.docs, 1)

        // le serveur ne voit que du chiffré : le jeton d'un second join est épuisé
        let tok2 = try await owner.createJoinToken()
        let intruder = try Web3CSyncClient(link: try GroupLink.parse(try await owner.makeLink(token: tok2.token).format()), deviceKey: DeviceKey())
        try await intruder.join(token: tok2.token, deviceName: "x")
        do { try await intruder.join(token: tok2.token, deviceName: "x"); XCTFail("jeton réutilisé") }
        catch { XCTAssertEqual(error as? SyncError, .forbidden) }
    }

    func testConflictResolvedByUpsert() async throws {
        let (a, b, _) = try await pair()
        try await a.putDoc(collection: "progress", logicalId: "k", payload: ["v": "a"], updatedAt: 100, ifMatch: 0)
        // b écrit sur une base périmée -> 409
        do { try await b.putDoc(collection: "progress", logicalId: "k", payload: ["v": "b"], updatedAt: 200, ifMatch: 0); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .conflict(seq: 1)) }
        // upsert : le u le plus récent gagne
        let r = try await b.upsert(collection: "progress", logicalId: "k", local: Candidate(payload: ["v": "b"], updatedAt: 200))
        XCTAssertTrue(r.wrote)
        let _v1 = try await a.getDoc(collection: "progress", logicalId: "k").payload
        XCTAssertEqual(_v1, ["v": "b"])
        // plus ancien : rien n'est écrit
        let r2 = try await a.upsert(collection: "progress", logicalId: "k", local: Candidate(payload: ["v": "old"], updatedAt: 50))
        XCTAssertFalse(r2.wrote)
        let _v2 = try await b.getDoc(collection: "progress", logicalId: "k").payload
        XCTAssertEqual(_v2, ["v": "b"])

        // conflit réel pendant la fusion : un autre appareil écrit entre le GET et le PUT
        let counter = Counter()
        let r3 = try await a.upsert(collection: "progress", logicalId: "k") { remote in
            if counter.next() == 1 {
                _ = try await b.upsert(collection: "progress", logicalId: "k", local: Candidate(payload: ["v": "race"], updatedAt: 300))
            }
            return Candidate(payload: ["v": "a2", "seen": .number(Double(remote?.seq ?? 0))], updatedAt: 400)
        }
        XCTAssertTrue(r3.wrote)
        XCTAssertEqual(counter.value, 2)
        let _v3 = try await b.getDoc(collection: "progress", logicalId: "k").payload["v"]
        XCTAssertEqual(_v3, "a2")
    }

    func testTombstoneAndRecreate() async throws {
        let (a, b, _) = try await pair()
        let s1 = try await a.putDoc(collection: "favorites", logicalId: "f1", payload: true, updatedAt: 1, ifMatch: 0)
        let s2 = try await a.deleteDoc(collection: "favorites", logicalId: "f1", ifMatch: s1)
        XCTAssertEqual(s2, 2)
        do { _ = try await b.getDoc(collection: "favorites", logicalId: "f1"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .gone(seq: 2)) }
        let page = try await b.changesAll(since: 0)
        XCTAssertEqual(page.tombstones.count, 1)
        let gk = await a.groupKey
        let k = Web3CCrypto.deriveKeys(try XCTUnwrap(gk))
        XCTAssertEqual(page.tombstones[0].docId, Web3CCrypto.docId(kId: k.id, collection: "favorites", logicalId: "f1"))
        XCTAssertTrue(page.items.isEmpty)
        // upsert recrée sur le tombstone
        let r = try await b.upsert(collection: "favorites", logicalId: "f1", local: Candidate(payload: false, updatedAt: 5))
        XCTAssertTrue(r.wrote)
        XCTAssertEqual(r.seq, 3)
        do { _ = try await a.getDoc(collection: "favorites", logicalId: "nope"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .notFound) }
    }

    func testPaginatedChanges() async throws {
        let (a, b, _) = try await pair()
        for i in 0..<7 {
            try await a.putDoc(collection: "progress", logicalId: "d\(i)", payload: .number(Double(i)), updatedAt: Int64(i), ifMatch: 0)
        }
        let p1 = try await b.changes(since: 0, limit: 3)
        XCTAssertEqual(p1.items.count, 3)
        XCTAssertTrue(p1.more)
        XCTAssertEqual(p1.next, 3)
        let all = try await b.changesAll(since: 0, pageSize: 3)
        XCTAssertEqual(all.items.map(\.seq), [1, 2, 3, 4, 5, 6, 7])
        XCTAssertEqual(all.items.map(\.logicalId), (0..<7).map { "d\($0)" })
        XCTAssertFalse(all.more)
        XCTAssertEqual(all.next, 7)
        XCTAssertTrue(all.rejected.isEmpty)
        let none = try await b.changes(since: 7)
        XCTAssertTrue(none.items.isEmpty)
        XCTAssertEqual(none.next, 7)
    }

    func testLiveStream() async throws {
        let (a, b, _) = try await pair()
        let events = b.stream(since: 0, initialBackoff: 0.2, maxBackoff: 1)
        let task = Task { () -> [StreamEvent] in
            var got: [StreamEvent] = []
            for try await e in events {
                got.append(e)
                if got.count == 2 { break }
            }
            return got
        }
        try await Task.sleep(nanoseconds: 500_000_000)
        let s = try await a.putDoc(collection: "progress", logicalId: "live", payload: 1, updatedAt: 1, ifMatch: 0)
        try await a.deleteDoc(collection: "progress", logicalId: "live", ifMatch: s)
        let got = try await withTimeout(10) { try await task.value }
        XCTAssertEqual(got.map(\.seq), [1, 2])
        XCTAssertEqual(got.map(\.deleted), [false, true])
        XCTAssertEqual(got[0].collection, "progress")
    }

    func testStreamResumesFromSince() async throws {
        let (a, b, _) = try await pair()
        try await a.putDoc(collection: "progress", logicalId: "x", payload: 1, updatedAt: 1, ifMatch: 0)
        try await a.putDoc(collection: "progress", logicalId: "y", payload: 1, updatedAt: 1, ifMatch: 0)
        let events = b.stream(since: 1)
        var first: StreamEvent?
        for try await e in events { first = e; break }
        XCTAssertEqual(first?.seq, 2)
    }

    func testStreamUnauthorizedFinishes() async throws {
        let stranger = newClient(gid: try GroupLink.generateGroupId(), kg: try GroupLink.generateGroupKey())
        do {
            for try await _ in stranger.stream() { XCTFail("événement inattendu") }
            XCTFail("le flux aurait dû échouer")
        } catch { XCTAssertEqual(error as? SyncError, .forbidden) }
    }

    func testRevocation() async throws {
        let (owner, other, otherKey) = try await pair()
        try await other.putDoc(collection: "progress", logicalId: "k", payload: 1, updatedAt: 1, ifMatch: 0)
        try await owner.revoke(device: otherKey.publicKeyB64)
        do { _ = try await other.info(); XCTFail() } catch { XCTAssertEqual(error as? SyncError, .forbidden) }
        do { _ = try await other.getDoc(collection: "progress", logicalId: "k"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .forbidden) }
        let _v4 = try await owner.members().count
        XCTAssertEqual(_v4, 1)
        // le propriétaire ne peut pas être révoqué
        do { try await owner.revoke(device: owner.devicePublicKeyB64); XCTFail() } catch { XCTAssertEqual(error as? SyncError, .notFound) }
        // purge
        try await owner.purgeGroup()
        do { _ = try await owner.info(); XCTFail() } catch { XCTAssertEqual(error as? SyncError, .forbidden) }
    }

    func testWrongGroupKeyCannotDecrypt() async throws {
        let key = DeviceKey()
        let owner = newClient(key)
        let creds = try await owner.createGroup()
        try await owner.putDoc(collection: "progress", logicalId: "k", payload: ["s": "secret"], updatedAt: 1, ifMatch: 0)
        // même appareil (donc membre) mais mauvaise clé de groupe
        let bad = newClient(key, gid: creds.groupId, kg: try GroupLink.generateGroupKey())
        do { _ = try await bad.getDoc(collection: "progress", logicalId: "k"); XCTFail() }
        catch { XCTAssertTrue([.notFound, .decryption, .integrity].contains(error as? SyncError), "\(error)") }
        let page = try await bad.changesAll(since: 0)
        XCTAssertTrue(page.items.isEmpty)
        XCTAssertEqual(page.rejected.count, 1)
        // bonne clé mais mauvais contexte : un autre groupe avec la même K_g ne peut pas rejouer l'enveloppe
        let _v5 = try await owner.changesAll(since: 0).items.count
        XCTAssertEqual(_v5, 1)
    }

    func testBlobs() async throws {
        let (a, b, _) = try await pair()
        let data = Data((0..<1000).map { UInt8($0 % 251) })
        try await a.putBlob(id: "seg-1", data: data)
        let _v6 = try await b.getBlob(id: "seg-1")
        XCTAssertEqual(_v6, data)
        let _v7 = try await b.getBlob(id: "seg-1", range: 10...19)
        XCTAssertEqual(_v7, data[10...19])
        try await a.deleteBlob(id: "seg-1")
        do { _ = try await b.getBlob(id: "seg-1"); XCTFail() } catch { XCTAssertEqual(error as? SyncError, .notFound) }
    }

    func testCommunityRatings() async throws {
        let c = CommunityClient(baseURL: base, powBits: 8)
        let kUser = try GroupLink.generateGroupKey()
        try await c.vote(contentKey: "movie:tmdb:603", profileId: "p1", kUser: kUser, rating: 7.5)
        try await c.vote(contentKey: "movie:tmdb:603", profileId: "p2", kUser: kUser, rating: 8)
        var agg = try await c.get(contentKey: "movie:tmdb:603")
        XCTAssertEqual(agg.count, 2)
        XCTAssertEqual(agg.sum, 15.5, accuracy: 1e-9)
        XCTAssertEqual(agg.avg, 7.75, accuracy: 1e-9)
        // un nouveau vote remplace l'ancien
        try await c.vote(contentKey: "movie:tmdb:603", profileId: "p1", kUser: kUser, rating: 7)
        agg = try await c.get(contentKey: "movie:tmdb:603")
        XCTAssertEqual(agg.sum, 15, accuracy: 1e-9)
        // retrait
        try await c.vote(contentKey: "movie:tmdb:603", profileId: "p2", kUser: kUser, rating: nil)
        let q = try await c.query(contentKeys: ["movie:tmdb:603", "movie:tmdb:1"])
        XCTAssertEqual(q["movie:tmdb:603"]?.count, 1)
        XCTAssertEqual(q["movie:tmdb:603"]?.avg ?? 0, 7, accuracy: 1e-9)
        // note hors bornes refusée, PoW insuffisant refusé
        do { try await c.vote(contentKey: "movie:tmdb:603", profileId: "p1", kUser: kUser, rating: 11); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .badRequest) }
        let weak = CommunityClient(baseURL: base, powBits: 0)
        var rejected = false
        for i in 0..<20 where !rejected {
            do { try await weak.vote(contentKey: "movie:tmdb:9", profileId: "w\(i)", kUser: kUser, rating: 5) }
            catch { rejected = (error as? SyncError == .forbidden) }
        }
        XCTAssertTrue(rejected, "un PoW à 0 bit devrait être refusé par un serveur à 8 bits")
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var value = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; value += 1; return value }
}

func withTimeout<T: Sendable>(_ seconds: Double, _ op: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { g in
        g.addTask { try await op() }
        g.addTask { try await Task.sleep(nanoseconds: UInt64(seconds * 1e9)); throw SyncError.transport("timeout") }
        let r = try await g.next()!
        g.cancelAll()
        return r
    }
}
