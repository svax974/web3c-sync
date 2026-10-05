import Foundation

/// Lien d'appairage : `web3c-link:v1?s=<urlServeur>&i=<instance>&g=<groupId>&t=<token>&k=<K_g>[&f=<empreinteTLS>]`
public struct GroupLink: Equatable, Sendable {
    public static let prefix = "web3c-link:v1?"

    public var serverURL: String
    public var instance: String
    public var groupId: String
    public var token: String
    public var groupKey: Data
    /// Empreinte SHA-256 (hex) du certificat serveur, pour un serveur personnel auto-signé.
    public var tlsFingerprint: String?

    public init(serverURL: String, instance: String, groupId: String, token: String, groupKey: Data, tlsFingerprint: String? = nil) {
        self.serverURL = serverURL
        self.instance = instance
        self.groupId = groupId
        self.token = token
        self.groupKey = groupKey
        self.tlsFingerprint = tlsFingerprint
    }

    private static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    private static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
    }

    public func format() -> String {
        var parts = [
            "s=\(Self.enc(serverURL))", "i=\(Self.enc(instance))", "g=\(Self.enc(groupId))",
            "t=\(Self.enc(token))", "k=\(Self.enc(B64.encode(groupKey)))",
        ]
        if let f = tlsFingerprint, !f.isEmpty { parts.append("f=\(Self.enc(f))") }
        return Self.prefix + parts.joined(separator: "&")
    }

    public init(parsing text: String) throws {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix(Self.prefix) else { throw SyncError.invalid("not a web3c-link:v1") }
        var q: [String: String] = [:]
        for pair in t.dropFirst(Self.prefix.count).split(separator: "&", omittingEmptySubsequences: true) {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard kv.count == 2, let v = String(kv[1]).removingPercentEncoding else { throw SyncError.invalid("malformed link") }
            q[String(kv[0])] = v
        }
        guard let s = q["s"], !s.isEmpty, URL(string: s) != nil,
              let i = q["i"], !i.isEmpty,
              let g = q["g"], let gb = B64.decode(g), gb.count == 16,
              let tok = q["t"], !tok.isEmpty,
              let k = q["k"], let kb = B64.decode(k), kb.count == 32
        else { throw SyncError.invalid("missing or invalid link field") }
        self.init(serverURL: s, instance: i, groupId: g, token: tok, groupKey: kb, tlsFingerprint: q["f"])
    }

    public static func parse(_ text: String) throws -> GroupLink { try GroupLink(parsing: text) }

    /// 16 octets aléatoires, base64url (22 caractères).
    public static func generateGroupId() throws -> String { B64.encode(try Randomness.bytes(16)) }

    /// 32 octets aléatoires.
    public static func generateGroupKey() throws -> Data { try Randomness.bytes(32) }
}
