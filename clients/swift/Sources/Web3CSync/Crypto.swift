import Foundation
import CryptoKit
import Security

// MARK: - Base64url (RFC 4648 §5, sans remplissage)

public enum B64 {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Décode strictement : alphabet url-safe uniquement, sans remplissage.
    public static func decode(_ string: String) -> Data? {
        for u in string.utf8 {
            switch u {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"):
                continue
            default:
                return nil
            }
        }
        if string.utf8.count % 4 == 1 { return nil }
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}

// MARK: - Aléa

public enum Randomness {
    public static func bytes(_ count: Int) throws -> Data {
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw SyncError.invalid("random generator failure") }
        return out
    }
}

// MARK: - Primitives du protocole

public struct DerivedKeys: Sendable, Equatable {
    public let enc: Data
    public let id: Data
    public let name: Data
}

public enum Web3CCrypto {
    public static let version = "web3c-sync/v1"
    public static let envelopeVersion: UInt8 = 0x01
    static let nonceLength = 12
    static let tagLength = 16

    // MARK: Encodage

    /// `u16(len(x)) || x`
    public static func field(_ x: Data) -> Data {
        precondition(x.count <= 0xFFFF, "field too long")
        var out = Data([UInt8(x.count >> 8), UInt8(x.count & 0xFF)])
        out.append(x)
        return out
    }

    public static func field(_ s: String) -> Data { field(Data(s.utf8)) }

    static func fields(_ parts: String...) -> Data {
        var out = Data()
        for p in parts { out.append(field(p)) }
        return out
    }

    static func u64(_ n: UInt64) -> Data {
        var out = Data(count: 8)
        for i in 0..<8 { out[i] = UInt8((n >> UInt64(56 - 8 * i)) & 0xFF) }
        return out
    }

    // MARK: Clés

    private static func hkdf(_ kg: Data, info: String) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: kg),
            salt: Data(version.utf8),
            info: Data(info.utf8),
            outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    public static func deriveKeys(_ kg: Data) -> DerivedKeys {
        DerivedKeys(enc: hkdf(kg, info: "enc"), id: hkdf(kg, info: "id"), name: hkdf(kg, info: "name"))
    }

    /// `docId = b64url(HMAC-SHA256(K_id, field(collection) || field(logicalId)))`
    public static func docId(kId: Data, collection: String, logicalId: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: fields(collection, logicalId), using: SymmetricKey(data: kId))
        return B64.encode(Data(mac))
    }

    // MARK: Bourrage

    public static func padme(_ length: Int) -> Int {
        if length < 2 { return length }
        let e = Int.bitWidth - length.leadingZeroBitCount - 1
        let s = Int.bitWidth - e.leadingZeroBitCount
        let z = e - s
        let mask = (1 << z) - 1
        return (length + mask) & ~mask
    }

    static func pad(_ p: Data) -> Data {
        let n = padme(p.count + 1)
        var m = p
        m.append(0x80)
        if n > m.count { m.append(Data(count: n - m.count)) }
        return m
    }

    static func unpad(_ m: Data) throws -> Data {
        var i = m.count - 1
        while i >= 0 && m[m.startIndex + i] == 0 { i -= 1 }
        guard i >= 0, m[m.startIndex + i] == 0x80 else { throw SyncError.decryption }
        return m.prefix(i)
    }

    // MARK: Enveloppe

    public static func aad(instance: String, groupId: String, collection: String, docId: String) -> Data {
        var out = Data(version.utf8)
        out.append(0)
        out.append(fields(instance, groupId, collection, docId))
        return out
    }

    /// Chiffre `plaintext` en enveloppe `0x01 || nonce || ct || tag`. `nonce` nil = aléatoire.
    public static func seal(kEnc: Data, aad: Data, plaintext: Data, nonce: Data? = nil) throws -> Data {
        let n = try nonce ?? Randomness.bytes(nonceLength)
        guard n.count == nonceLength, kEnc.count == 32 else { throw SyncError.invalid("bad key or nonce length") }
        let box = try AES.GCM.seal(pad(plaintext), using: SymmetricKey(data: kEnc),
                                   nonce: AES.GCM.Nonce(data: n), authenticating: aad)
        var out = Data([envelopeVersion])
        out.append(n)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    public static func open(kEnc: Data, aad: Data, envelope: Data) throws -> Data {
        let env = Data(envelope) // normalise les indices
        guard env.count >= 1 + nonceLength + tagLength + 1, env[0] == envelopeVersion, kEnc.count == 32 else {
            throw SyncError.decryption
        }
        do {
            let nonce = try AES.GCM.Nonce(data: env[1..<(1 + nonceLength)])
            let ct = env[(1 + nonceLength)..<(env.count - tagLength)]
            let tag = env[(env.count - tagLength)...]
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            let m = try AES.GCM.open(box, using: SymmetricKey(data: kEnc), authenticating: aad)
            return try unpad(m)
        } catch {
            throw SyncError.decryption
        }
    }

    // MARK: Requêtes signées

    public static func bodyHash(_ body: Data) -> String {
        SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    }

    public static func canonical(method: String, pathQuery: String, timestamp: String, nonce: String,
                                 bodyHash: String, instance: String) -> Data {
        Data("\(version)\n\(method)\n\(pathQuery)\n\(timestamp)\n\(nonce)\n\(bodyHash)\n\(instance)".utf8)
    }

    public static func sign(_ key: DeviceKey, canonical: Data) throws -> String {
        B64.encode(try key.sign(canonical))
    }

    public static func verify(publicKey: Data, canonical: Data, signature: String) -> Bool {
        guard let sig = B64.decode(signature),
              let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(sig, for: canonical)
    }

    // MARK: Notes communautaires

    /// Texte décimal le plus court : `7`, `7.5`, `null` — jamais `7.0`, jamais d'exposant.
    public static func ratingText(_ r: Double?) -> String {
        guard let r = r, r.isFinite else { return "null" }
        var s = "\(r)"                       // plus courte représentation aller-retour, mais "7.0" / "1e-05"
        if s.contains("e") || s.contains("E") {
            if let d = Decimal(string: s) { s = NSDecimalNumber(decimal: d).description(withLocale: nil) }
            if s.contains("e") || s.contains("E") { s = String(format: "%.17f", r) }
        }
        if s.contains(".") {
            while s.hasSuffix("0") { s.removeLast() }
            if s.hasSuffix(".") { s.removeLast() }
        }
        return s == "" ? "0" : s
    }

    public static func pseudonym(kUser: Data, profileId: String, contentKey: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: fields("rating", profileId, contentKey), using: SymmetricKey(data: kUser))
        return B64.encode(Data(mac))
    }

    public static func powDigest(contentKey: String, pseudonym: String, rating: Double?, n: UInt64) -> Data {
        var buf = field(contentKey)
        buf.append(field(pseudonym))
        buf.append(Data(ratingText(rating).utf8))
        buf.append(u64(n))
        return Data(SHA256.hash(data: buf))
    }

    static func leadingZeroBits(_ h: Data) -> Int {
        var n = 0
        for b in h {
            if b == 0 { n += 8; continue }
            return n + b.leadingZeroBitCount
        }
        return n
    }

    public static func powOk(contentKey: String, pseudonym: String, rating: Double?, n: UInt64, powBits: Int) -> Bool {
        leadingZeroBits(powDigest(contentKey: contentKey, pseudonym: pseudonym, rating: rating, n: n)) >= powBits
    }

    /// Plus petit `n` valide (bloquant).
    public static func solvePow(contentKey: String, pseudonym: String, rating: Double?, powBits: Int) -> UInt64 {
        var n: UInt64 = 0
        while !powOk(contentKey: contentKey, pseudonym: pseudonym, rating: rating, n: n, powBits: powBits) { n += 1 }
        return n
    }

    /// Version coopérative : cède régulièrement la main et respecte l'annulation.
    public static func solvePowAsync(contentKey: String, pseudonym: String, rating: Double?, powBits: Int) async throws -> UInt64 {
        var n: UInt64 = 0
        while true {
            if powOk(contentKey: contentKey, pseudonym: pseudonym, rating: rating, n: n, powBits: powBits) { return n }
            n += 1
            if n % 2048 == 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
        }
    }
}
