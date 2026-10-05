import XCTest
@testable import Web3CSync

final class CryptoTests: XCTestCase {
    let kg = Data((0..<32).map(UInt8.init))
    lazy var keys = Web3CCrypto.deriveKeys(kg)

    private func aad(_ i: String = "iptv", _ g: String = "AAAAAAAAAAAAAAAAAAAAAA", _ c: String = "progress", _ d: String = "doc") -> Data {
        Web3CCrypto.aad(instance: i, groupId: g, collection: c, docId: d)
    }

    func testRoundTripVariousSizes() throws {
        for n in [0, 1, 2, 15, 16, 17, 255, 256, 1000, 5000] {
            let pt = Data((0..<n).map { UInt8($0 & 0xFF) })
            let env = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: pt)
            XCTAssertEqual(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: env), pt)
            // taille = 1 + 12 + padme(n+1) + 16
            XCTAssertEqual(env.count, 1 + 12 + Web3CCrypto.padme(n + 1) + 16)
        }
    }

    func testPlaintextEndingWithZerosAndMarker() throws {
        let pt = Data([0x80, 0, 0, 0x80, 0, 0])
        let env = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: pt)
        XCTAssertEqual(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: env), pt)
    }

    func testRandomNonceDiffers() throws {
        let a = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data("x".utf8))
        let b = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data("x".utf8))
        XCTAssertNotEqual(a, b)
    }

    func testTamperRejected() throws {
        let env = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data("hello".utf8))
        for i in 0..<env.count {
            var t = env
            t[i] ^= 0x01
            XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: t), "byte \(i)")
        }
        XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: env.dropLast()))
        XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: Data([1, 2, 3])))
        var v2 = env
        v2[0] = 0x02
        XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.enc, aad: aad(), envelope: v2))
    }

    func testAADBinding() throws {
        let env = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data("hello".utf8))
        let wrong = [aad("banking"), aad("iptv", "BAAAAAAAAAAAAAAAAAAAAA"), aad("iptv", "AAAAAAAAAAAAAAAAAAAAAA", "ratings"),
                     aad("iptv", "AAAAAAAAAAAAAAAAAAAAAA", "progress", "other")]
        for a in wrong { XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.enc, aad: a, envelope: env)) }
        XCTAssertThrowsError(try Web3CCrypto.open(kEnc: keys.id, aad: aad(), envelope: env))
    }

    func testAADLengthPrefixPreventsAmbiguity() {
        XCTAssertNotEqual(aad("ab", "c"), aad("a", "bc"))
    }

    func testPaddingHidesLength() throws {
        let a = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data(count: 1000))
        let b = try Web3CCrypto.seal(kEnc: keys.enc, aad: aad(), plaintext: Data(count: 1010))
        XCTAssertEqual(a.count, b.count)
    }

    func testGroupLinkRoundTrip() throws {
        let link = GroupLink(serverURL: "https://sync.example.com:8443/base", instance: "iptv",
                             groupId: try GroupLink.generateGroupId(), token: try B64.encode(Randomness.bytes(16)),
                             groupKey: try GroupLink.generateGroupKey(), tlsFingerprint: "AB:CD&=?")
        let text = link.format()
        XCTAssertTrue(text.hasPrefix("web3c-link:v1?s=https%3A%2F%2Fsync.example.com%3A8443%2Fbase&i=iptv&g="))
        XCTAssertEqual(try GroupLink.parse(text), link)
        var noF = link
        noF.tlsFingerprint = nil
        XCTAssertFalse(noF.format().contains("&f="))
        XCTAssertEqual(try GroupLink.parse(noF.format()), noF)
        XCTAssertThrowsError(try GroupLink.parse("http://x"))
        XCTAssertThrowsError(try GroupLink.parse("web3c-link:v1?s=http%3A%2F%2Fx&i=iptv"))
        XCTAssertEqual(link.groupId.count, 22)
        XCTAssertEqual(link.groupKey.count, 32)
    }

    func testDeviceKeyStore() throws {
        let store = MemoryDeviceKeyStore()
        XCTAssertNil(try store.load())
        let k = try store.loadOrCreate()
        XCTAssertEqual(try store.loadOrCreate().seed, k.seed)
        XCTAssertEqual(try DeviceKey(seed: k.seed).publicKey, k.publicKey)
        try store.delete()
        XCTAssertNil(try store.load())
    }

    func testFingerprintNormalization() {
        let hex = String(repeating: "ab", count: 32)
        XCTAssertEqual(normalizeFingerprint(hex.uppercased()), hex)
        XCTAssertEqual(normalizeFingerprint(stride(from: 0, to: 64, by: 2).map { String(hex.dropFirst($0).prefix(2)) }.joined(separator: ":")), hex)
        XCTAssertNil(normalizeFingerprint("zz"))
    }
}
