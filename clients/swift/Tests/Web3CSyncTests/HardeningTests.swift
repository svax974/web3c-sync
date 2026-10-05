import XCTest
import Network
@testable import Web3CSync

/// Transport factice : répond par une closure, sans réseau.
final class MockTransport: Web3CTransport, @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest) -> (status: Int, body: Data, headers: [String: String])
    private let handler: Handler
    private let lock = NSLock()
    private var _calls = 0
    var calls: Int { lock.lock(); defer { lock.unlock() }; return _calls }
    init(_ handler: @escaping Handler) { self.handler = handler }
    private func bump() { lock.lock(); _calls += 1; lock.unlock() }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        bump()
        let r = handler(request)
        let resp = HTTPURLResponse(url: request.url!, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: r.headers)!
        return (r.body, resp)
    }

    func lines(for request: URLRequest) async throws -> (HTTPURLResponse, AsyncThrowingStream<String, Error>) {
        throw SyncError.transport("unsupported")
    }
}

/// Mini serveur HTTP local (Network.framework) pour tester les redirections.
final class MiniServer: @unchecked Sendable {
    private let listener: NWListener
    private let lock = NSLock()
    private var _paths: [String] = []
    private(set) var port: UInt16 = 0
    var paths: [String] { lock.lock(); defer { lock.unlock() }; return _paths }

    init(respond: @escaping @Sendable (String, UInt16) -> String) throws {
        listener = try NWListener(using: .tcp, on: .any)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { [weak self] st in
            if case .ready = st { self?.port = self?.listener.port?.rawValue ?? 0; ready.signal() }
        }
        listener.newConnectionHandler = { [weak self] conn in
            conn.start(queue: .global())
            conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, _ in
                guard let self = self, let data = data else { conn.cancel(); return }
                let line = String(decoding: data, as: UTF8.self).split(separator: "\r\n").first.map(String.init) ?? ""
                let path = line.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
                self.lock.lock(); self._paths.append(path); self.lock.unlock()
                conn.send(content: Data(respond(path, self.port).utf8), completion: .contentProcessed { _ in conn.cancel() })
            }
        }
        listener.start(queue: .global())
        _ = ready.wait(timeout: .now() + 5)
    }

    func stop() { listener.cancel() }
}

final class HardeningTests: XCTestCase {
    let kg = Data((0..<32).map(UInt8.init))
    let gid = "AAAAAAAAAAAAAAAAAAAAAA"
    let fixedNow = Date(timeIntervalSince1970: 1_760_000_000)
    let base = URL(string: "http://127.0.0.1:1")!

    func client(_ t: Web3CTransport, floor: (@Sendable (String, String) -> Int64?)? = nil) -> Web3CSyncClient {
        let now = fixedNow
        return Web3CSyncClient(baseURL: base, instance: "iptv", deviceKey: DeviceKey(), groupId: gid, groupKey: kg,
                               transport: t, counterFloor: floor, clock: { now })
    }

    func docId(_ c: String, _ k: String) -> String {
        Web3CCrypto.docId(kId: Web3CCrypto.deriveKeys(kg).id, collection: c, logicalId: k)
    }

    func envelope(_ c: String, _ k: String, json: String) throws -> String {
        let keys = Web3CCrypto.deriveKeys(kg)
        let aad = Web3CCrypto.aad(instance: "iptv", groupId: gid, collection: c, docId: docId(c, k))
        return B64.encode(try Web3CCrypto.seal(kEnc: keys.enc, aad: aad, plaintext: Data(json.utf8)))
    }

    func changesBody(_ items: [[String: Any]], next: Int, more: Bool = false) -> Data {
        try! JSONSerialization.data(withJSONObject: ["items": items, "next": next, "more": more])
    }

    func item(_ c: String, _ k: String, seq: Int, json: String) throws -> [String: Any] {
        ["collection": c, "docId": docId(c, k), "seq": seq, "deleted": false, "updatedAt": 1, "env": try envelope(c, k, json: json)]
    }

    // MARK: Documents

    func testMissingCounterRejected() async throws {
        let body = changesBody([try item("progress", "a", seq: 1, json: #"{"v":1,"u":5,"k":"a","d":1}"#),
                                try item("progress", "b", seq: 2, json: #"{"v":1,"u":5,"c":0,"k":"b","d":1}"#),
                                try item("progress", "ok", seq: 3, json: #"{"v":1,"u":5,"c":1,"k":"ok","d":1}"#)], next: 3)
        let c = client(MockTransport { _ in (200, body, [:]) })
        let page = try await c.changes(since: 0)
        XCTAssertEqual(page.items.map(\.logicalId), ["ok"])
        XCTAssertEqual(page.rejected.map(\.seq), [1, 2])
        XCTAssertEqual(page.rejected.map(\.error), [.missingCounter, .missingCounter])
        // getDoc : erreur explicite
        let env = try envelope("progress", "a", json: #"{"v":1,"u":5,"k":"a","d":1}"#)
        let g = client(MockTransport { _ in (200, Data(base64Encoded: env.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - env.count % 4) % 4))!, ["X-Seq": "1"]) })
        do { _ = try await g.getDoc(collection: "progress", logicalId: "a"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .missingCounter) }
    }

    func testMalformedDelAndDRejected() async throws {
        let body = changesBody([try item("progress", "a", seq: 1, json: #"{"v":1,"u":5,"c":1,"k":"a"}"#),                 // ni d ni del
                                try item("progress", "b", seq: 2, json: #"{"v":1,"u":5,"c":1,"k":"b","d":1,"del":true}"#), // d + del
                                try item("progress", "n", seq: 3, json: #"{"v":1,"u":5,"c":1,"k":"n","d":null}"#)],       // d:null valide
                               next: 3)
        let page = try await client(MockTransport { _ in (200, body, [:]) }).changes(since: 0)
        XCTAssertEqual(page.items.map(\.logicalId), ["n"])
        XCTAssertEqual(page.rejected.count, 2)
    }

    func testCounterFloor() async throws {
        let body = changesBody([try item("progress", "a", seq: 1, json: #"{"v":1,"u":5,"c":3,"k":"a","d":1}"#),
                                try item("progress", "b", seq: 2, json: #"{"v":1,"u":5,"c":4,"k":"b","d":1}"#)], next: 2)
        let idA = docId("progress", "a")
        let c = client(MockTransport { _ in (200, body, [:]) }, floor: { col, id in
            XCTAssertEqual(col, "progress")
            return id == idA ? 4 : 4
        })
        let page = try await c.changes(since: 0)
        XCTAssertEqual(page.items.map(\.logicalId), ["b"])            // c == plancher accepté
        XCTAssertEqual(page.rejected.map(\.error), [.rollback])
        XCTAssertEqual(page.rejected.first?.docId, idA)
        // getDoc lève .rollback
        let env = try envelope("progress", "a", json: #"{"v":1,"u":5,"c":3,"k":"a","d":1}"#)
        let raw = B64.decode(env)!
        let g = client(MockTransport { _ in (200, raw, ["X-Seq": "1"]) }, floor: { _, _ in 4 })
        do { _ = try await g.getDoc(collection: "progress", logicalId: "a"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .rollback) }
    }

    func testCursorRollback() async throws {
        let c = client(MockTransport { _ in (200, self.changesBody([], next: 4), [:]) })
        do { _ = try await c.changes(since: 10); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .rollback) }
        let ok = try await c.changes(since: 4)               // next == since : autorisé
        XCTAssertEqual(ok.next, 4)
        do { _ = try await c.changesAll(since: 10); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .rollback) }
    }

    func testChangesAllPageCapAndStall() async throws {
        let n = Counter()
        let c = client(MockTransport { _ in
            let v = n.next()
            return (200, self.changesBody([], next: v, more: true), [:])
        })
        do { _ = try await c.changesAll(since: 0, maxPages: 5); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .server(status: 200, code: "too_many_pages")) }
        XCTAssertEqual(n.value, 5)
        // curseur qui ne progresse pas : arrêt (pas de boucle infinie)
        let stuck = client(MockTransport { _ in (200, self.changesBody([], next: 7, more: true), [:]) })
        let r = try await stuck.changesAll(since: 7)
        XCTAssertEqual(r.next, 7)
    }

    func testUpdatedAtClamp() async throws {
        let nowMs = Int64(fixedNow.timeIntervalSince1970 * 1000)
        let far = nowMs + 3_600_000
        let near = nowMs + 60_000
        let body = changesBody([try item("progress", "far", seq: 1, json: "{\"v\":1,\"u\":\(far),\"c\":1,\"k\":\"far\",\"d\":1}"),
                                try item("progress", "near", seq: 2, json: "{\"v\":1,\"u\":\(near),\"c\":1,\"k\":\"near\",\"d\":1}")], next: 2)
        let page = try await client(MockTransport { _ in (200, body, [:]) }).changes(since: 0)
        XCTAssertEqual(page.items[0].updatedAt, nowMs + 300_000)
        XCTAssertEqual(page.items[0].rawUpdatedAt, far)
        XCTAssertEqual(page.items[1].updatedAt, near)
        XCTAssertEqual(page.items[1].rawUpdatedAt, near)
    }

    func testMarkerDecoding() async throws {
        let body = changesBody([try item("progress", "m", seq: 1, json: #"{"v":1,"u":5,"c":2,"k":"m","del":true}"#)], next: 1)
        let page = try await client(MockTransport { _ in (200, body, [:]) }).changes(since: 0)
        XCTAssertEqual(page.items.count, 1)
        XCTAssertTrue(page.items[0].deleted)
        XCTAssertEqual(page.items[0].counter, 2)
        XCTAssertEqual(page.items[0].payload, .null)
    }

    func testServerTombstoneNotAuthenticated() {
        let t = Tombstone(collection: "x", docId: "y", seq: 1, updatedAt: 0)
        XCTAssertFalse(t.isAuthenticated)
    }

    // MARK: Transport

    func testHTTPRefusedOutsideLoopback() async throws {
        let m = MockTransport { _ in (200, Data("{}".utf8), [:]) }
        for u in ["http://example.com", "http://192.168.1.10:8080", "ftp://127.0.0.1", "http://localhost.evil.com"] {
            let c = Web3CSyncClient(baseURL: URL(string: u)!, instance: "iptv", deviceKey: DeviceKey(), groupId: gid, groupKey: kg, transport: m)
            do { _ = try await c.info(); XCTFail(u) }
            catch { guard case .invalid = error as? SyncError else { return XCTFail("\(u): \(error)") } }
            let com = CommunityClient(baseURL: URL(string: u)!, powBits: 0, transport: m)
            do { _ = try await com.get(contentKey: "movie:tmdb:1"); XCTFail(u) }
            catch { guard case .invalid = error as? SyncError else { return XCTFail("\(u): \(error)") } }
        }
        XCTAssertEqual(m.calls, 0, "aucune requête ne doit partir")
        // lien http:// hors loopback : l'init lève
        let link = GroupLink(serverURL: "http://example.com", instance: "iptv", groupId: gid, token: "t", groupKey: kg)
        XCTAssertThrowsError(try Web3CSyncClient(link: link, deviceKey: DeviceKey(), transport: m))
        // loopback autorisé
        for u in ["http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1", "https://example.com"] {
            XCTAssertNil(validateEndpoint(URL(string: u)!, tlsFingerprint: nil), u)
        }
        let ok = Web3CSyncClient(baseURL: URL(string: "http://localhost:9")!, instance: "iptv", deviceKey: DeviceKey(),
                                 groupId: gid, groupKey: kg, transport: MockTransport { _ in (200, Data(#"{"instance":"iptv","seq":0,"docs":0,"bytes":0,"purgeAt":0}"#.utf8), [:]) })
        _ = try await ok.info()
    }

    func testInvalidFingerprintFailsClosed() async throws {
        let m = MockTransport { _ in (200, Data("{}".utf8), [:]) }
        let c = Web3CSyncClient(baseURL: URL(string: "https://example.com")!, instance: "iptv", deviceKey: DeviceKey(),
                                groupId: gid, groupKey: kg, tlsFingerprint: "not-a-fingerprint", transport: m)
        do { _ = try await c.info(); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .invalid("invalid TLS fingerprint")) }
        XCTAssertEqual(m.calls, 0)
        // lien avec empreinte invalide : l'init lève
        let link = GroupLink(serverURL: "https://example.com", instance: "iptv", groupId: gid, token: "t", groupKey: kg, tlsFingerprint: "zz")
        XCTAssertThrowsError(try Web3CSyncClient(link: link, deviceKey: DeviceKey()))
        // Communauté
        let com = CommunityClient(baseURL: URL(string: "https://example.com")!, tlsFingerprint: "zz", transport: m)
        do { _ = try await com.get(contentKey: "movie:tmdb:1"); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .invalid("invalid TLS fingerprint")) }
        // Transport par défaut (sans transport injecté) : échoue sans réseau
        let t = URLSessionTransport(tlsFingerprint: "zz")
        do { _ = try await t.data(for: URLRequest(url: URL(string: "https://example.com")!)); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .invalid("invalid TLS fingerprint")) }
        do { _ = try await t.lines(for: URLRequest(url: URL(string: "https://example.com")!)); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .invalid("invalid TLS fingerprint")) }
        // Empreinte vide ou valide : pas d'erreur de configuration
        XCTAssertNil(validateEndpoint(URL(string: "https://example.com")!, tlsFingerprint: ""))
        XCTAssertNil(validateEndpoint(URL(string: "https://example.com")!, tlsFingerprint: String(repeating: "ab", count: 32)))
    }

    func testRedirectNotFollowed() async throws {
        let srv = try MiniServer { path, port in
            if path.hasPrefix("/a") {
                return "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:\(port)/b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        }
        defer { srv.stop() }
        XCTAssertNotEqual(srv.port, 0)
        let t = URLSessionTransport()
        let (_, resp) = try await t.data(for: URLRequest(url: URL(string: "http://127.0.0.1:\(srv.port)/a")!))
        XCTAssertEqual(resp.statusCode, 307)
        XCTAssertFalse(srv.paths.contains { $0.hasPrefix("/b") }, "la redirection ne doit pas être suivie")
        // Via le client : une 3xx devient SyncError.server
        let c = Web3CSyncClient(baseURL: URL(string: "http://127.0.0.1:\(srv.port)/a")!, instance: "iptv", deviceKey: DeviceKey(),
                                groupId: gid, groupKey: kg)
        do { _ = try await c.info(); XCTFail() }
        catch { XCTAssertEqual(error as? SyncError, .server(status: 307, code: nil)) }
        XCTAssertFalse(srv.paths.contains { $0.hasPrefix("/b") })
    }

    // MARK: Communauté

    func testVoteBodyAndKeyValidation() async throws {
        let captured = Box<Data?>(nil)
        let m = MockTransport { req in captured.value = req.httpBody; return (200, Data("{}".utf8), [:]) }
        let now = fixedNow
        let c = CommunityClient(baseURL: base, powBits: 8, transport: m, clock: { now })
        let k = Web3CCrypto.deriveKeys(kg).rating
        try await c.vote(contentKey: "movie:tmdb:603", profileId: "p", kUser: k, rating: 7.5)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(captured.value)) as? [String: Any])
        XCTAssertEqual(Set(obj.keys), ["p", "r", "t", "n"])
        XCTAssertEqual(obj["t"] as? Int, 1_760_000_000)
        let p = obj["p"] as! String, n = (obj["n"] as! NSNumber).uint64Value
        XCTAssertEqual(p, Web3CCrypto.pseudonym(kRating: k, profileId: "p", contentKey: "movie:tmdb:603"))
        XCTAssertTrue(Web3CCrypto.powOk(contentKey: "movie:tmdb:603", pseudonym: p, rating: 7.5, t: 1_760_000_000, n: n, powBits: 8))
        // le PoW est lié à t
        XCTAssertNotEqual(Web3CCrypto.powDigest(contentKey: "a", pseudonym: "p", rating: 1, t: 1, n: 0),
                          Web3CCrypto.powDigest(contentKey: "a", pseudonym: "p", rating: 1, t: 2, n: 0))
        for bad in ["movie:tmdb:", "movie:tmdb:1234567890", "movie:imdb:1", "anime:tmdb:1", "movie:tmdb:1\n", "Movie:tmdb:1", "movie:tmdb:-1", "movie:tmdb:1:2", "", "movie:tmdb:١"] {
            do { try await c.vote(contentKey: bad, profileId: "p", kUser: k, rating: 5); XCTFail(bad) }
            catch { guard case .invalid = error as? SyncError else { return XCTFail("\(bad): \(error)") } }
        }
        for good in ["movie:tmdb:1", "tv:tmdb:123456789", "series:tmdb:0"] {
            try await c.vote(contentKey: good, profileId: "p", kUser: k, rating: 5)
        }
    }

    func testVote409IsConflict() async throws {
        let m = MockTransport { _ in (409, Data(#"{"error":"conflict"}"#.utf8), [:]) }
        let c = CommunityClient(baseURL: base, powBits: 0, transport: m)
        do { try await c.vote(contentKey: "movie:tmdb:1", profileId: "p", kUser: kg, rating: 5); XCTFail() }
        catch { guard case .conflict = error as? SyncError else { return XCTFail("\(error)") } }
    }
}

final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _v: T
    init(_ v: T) { _v = v }
    var value: T { get { lock.lock(); defer { lock.unlock() }; return _v } set { lock.lock(); _v = newValue; lock.unlock() } }
}
