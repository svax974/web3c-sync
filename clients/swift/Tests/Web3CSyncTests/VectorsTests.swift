import XCTest
@testable import Web3CSync

final class VectorsTests: XCTestCase {
    private func load() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("spec/vectors/v1.json")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func sec(_ v: [String: Any], _ k: String) throws -> [String: Any] {
        try XCTUnwrap(v[k] as? [String: Any])
    }

    private func b64(_ s: String) throws -> Data { try XCTUnwrap(B64.decode(s)) }

    func testVersion() throws {
        XCTAssertEqual(try load()["version"] as? String, Web3CCrypto.version)
    }

    func testHKDF() throws {
        let h = try sec(try load(), "hkdf")
        let keys = Web3CCrypto.deriveKeys(try b64(h["kg"] as! String))
        XCTAssertEqual(B64.encode(keys.enc), h["enc"] as? String)
        XCTAssertEqual(B64.encode(keys.id), h["id"] as? String)
        XCTAssertEqual(B64.encode(keys.name), h["name"] as? String)
    }

    func testDocId() throws {
        let v = try load()
        let h = try sec(v, "hkdf"), d = try sec(v, "docId")
        let keys = Web3CCrypto.deriveKeys(try b64(h["kg"] as! String))
        XCTAssertEqual(Web3CCrypto.docId(kId: keys.id, collection: d["collection"] as! String, logicalId: d["logicalId"] as! String),
                       d["docId"] as? String)
    }

    func testPadme() throws {
        let p = try sec(try load(), "padme")
        let ins = p["in"] as! [Int], outs = p["out"] as! [Int]
        XCTAssertEqual(ins.count, outs.count)
        for (i, o) in zip(ins, outs) { XCTAssertEqual(Web3CCrypto.padme(i), o, "padme(\(i))") }
    }

    func testSeal() throws {
        let v = try load()
        let keys = Web3CCrypto.deriveKeys(try b64(try sec(v, "hkdf")["kg"] as! String))
        let s = try sec(v, "seal")
        let aad = Web3CCrypto.aad(instance: s["instance"] as! String, groupId: s["groupId"] as! String,
                                  collection: s["collection"] as! String, docId: s["docId"] as! String)
        XCTAssertEqual(B64.encode(aad), s["aad"] as? String)
        let pt = Data((s["plaintext"] as! String).utf8)
        let env = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad, plaintext: pt, nonce: try b64(s["nonce"] as! String))
        XCTAssertEqual(B64.encode(env), s["envelope"] as? String)
        let opened = try Web3CCrypto.open(kEnc: keys.enc, aad: aad, envelope: try b64(s["envelope"] as! String))
        XCTAssertEqual(opened, pt)
    }

    func testRequestSignature() throws {
        let r = try sec(try load(), "request")
        let body = Data((r["body"] as! String).utf8)
        XCTAssertEqual(Web3CCrypto.bodyHash(body), r["bodyHash"] as? String)
        let canon = Web3CCrypto.canonical(method: r["method"] as! String, pathQuery: r["path"] as! String,
                                          timestamp: r["timestamp"] as! String, nonce: r["nonce"] as! String,
                                          bodyHash: r["bodyHash"] as! String, instance: r["instance"] as! String)
        XCTAssertEqual(String(decoding: canon, as: UTF8.self), r["canonical"] as? String)
        let key = try DeviceKey(seed: try b64(r["seed"] as! String))
        XCTAssertEqual(key.publicKeyB64, r["pub"] as? String)
        let sig = try Web3CCrypto.sign(key, canonical: canon)
        // CryptoKit produit des signatures Ed25519 randomisées (valides, mais pas celles de RFC 8032) :
        // on exige donc que notre signature soit valide ET que la signature de référence soit acceptée.
        XCTAssertEqual(B64.decode(sig)?.count, 64)
        XCTAssertTrue(Web3CCrypto.verify(publicKey: key.publicKey, canonical: canon, signature: sig))
        XCTAssertTrue(Web3CCrypto.verify(publicKey: key.publicKey, canonical: canon, signature: r["signature"] as! String))
    }

    private func check(contentKey: String, pseudonym: String?, r: Any, text: String, n: UInt64, digest: String, bits: Int?) throws {
        let rating: Double? = (r is NSNull) ? nil : (r as! NSNumber).doubleValue
        XCTAssertEqual(Web3CCrypto.ratingText(rating), text)
        let p = pseudonym ?? "x"
        let d = Web3CCrypto.powDigest(contentKey: contentKey, pseudonym: p, rating: rating, n: n)
        XCTAssertEqual(B64.encode(d), digest)
        if let bits = bits {
            XCTAssertTrue(Web3CCrypto.powOk(contentKey: contentKey, pseudonym: p, rating: rating, n: n, powBits: bits))
        }
    }

    func testRating() throws {
        let v = try load()
        let keys = Web3CCrypto.deriveKeys(try b64(try sec(v, "hkdf")["kg"] as! String))
        let r = try sec(v, "rating")
        XCTAssertEqual(r["kUser"] as? String, "id")
        let ck = r["contentKey"] as! String
        let p = Web3CCrypto.pseudonym(kUser: keys.id, profileId: r["profileId"] as! String, contentKey: ck)
        XCTAssertEqual(p, r["pseudonym"] as? String)
        try check(contentKey: ck, pseudonym: p, r: r["r"]!, text: r["ratingText"] as! String,
                  n: (r["n"] as! NSNumber).uint64Value, digest: r["digest"] as! String, bits: r["powBits"] as? Int)
        // Le plus petit n valide est bien celui du vecteur.
        let solved = Web3CCrypto.solvePow(contentKey: ck, pseudonym: p, rating: 7.5, powBits: r["powBits"] as! Int)
        XCTAssertEqual(solved, (r["n"] as! NSNumber).uint64Value)
    }

    func testRatingCases() throws {
        let v = try load()
        let keys = Web3CCrypto.deriveKeys(try b64(try sec(v, "hkdf")["kg"] as! String))
        let base = try sec(v, "rating")
        let ck = base["contentKey"] as! String
        let p = Web3CCrypto.pseudonym(kUser: keys.id, profileId: base["profileId"] as! String, contentKey: ck)
        for c in try XCTUnwrap(v["ratingCases"] as? [[String: Any]]) {
            try check(contentKey: ck, pseudonym: p, r: c["r"]!, text: c["ratingText"] as! String,
                      n: (c["n"] as! NSNumber).uint64Value, digest: c["digest"] as! String, bits: base["powBits"] as? Int)
        }
    }

    func testRatingTextShortest() {
        XCTAssertEqual(Web3CCrypto.ratingText(7), "7")
        XCTAssertEqual(Web3CCrypto.ratingText(7.0), "7")
        XCTAssertEqual(Web3CCrypto.ratingText(7.5), "7.5")
        XCTAssertEqual(Web3CCrypto.ratingText(0), "0")
        XCTAssertEqual(Web3CCrypto.ratingText(10), "10")
        XCTAssertEqual(Web3CCrypto.ratingText(nil), "null")
        XCTAssertEqual(Web3CCrypto.ratingText(0.00001), "0.00001")
        XCTAssertEqual(Web3CCrypto.ratingText(1e21), "1000000000000000000000")
        XCTAssertEqual(Web3CCrypto.ratingText(8.25), "8.25")
        XCTAssertEqual(Web3CCrypto.ratingText(-1.5), "-1.5")
    }
}
