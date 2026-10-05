import Foundation
import CryptoKit
import Security

/// Transport HTTP injectable (tests sans réseau, épinglage TLS).
public protocol Web3CTransport: Sendable {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
    /// Flux de lignes (SSE). Les lignes vides sont conservées (elles terminent un événement).
    func lines(for request: URLRequest) async throws -> (HTTPURLResponse, AsyncThrowingStream<String, Error>)
}

/// Normalise une empreinte : hex (avec ou sans ':'), ou base64url de 32 octets -> hex minuscule.
public func normalizeFingerprint(_ s: String) -> String? {
    let hex = s.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "").lowercased()
    if hex.count == 64, hex.allSatisfy({ $0.isHexDigit }) { return hex }
    if let d = B64.decode(s), d.count == 32 { return d.map { String(format: "%02x", $0) }.joined() }
    return nil
}

/// Vérifie la configuration réseau commune aux clients : `https://` obligatoire sauf hôte loopback (127.0.0.1, ::1,
/// localhost) ; une empreinte TLS non vide mais invalide est une erreur (fail-closed, jamais d'épinglage désactivé en silence).
func validateEndpoint(_ url: URL, tlsFingerprint: String?) -> SyncError? {
    switch url.scheme?.lowercased() {
    case "https": break
    case "http":
        var host = (url.host ?? "").lowercased()
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard host == "127.0.0.1" || host == "::1" || host == "localhost" else {
            return .invalid("http:// refused outside loopback")
        }
    default:
        return .invalid("unsupported url scheme")
    }
    if let f = tlsFingerprint, !f.isEmpty, normalizeFingerprint(f) == nil {
        return .invalid("invalid TLS fingerprint")
    }
    return nil
}

final class PinningDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    let expected: String?

    init(expected: String?) { self.expected = expected }

    /// Les redirections ne sont jamais suivies : elles rejouent des en-têtes signés (et le jeton admin) vers un autre
    /// hôte. La réponse 3xx est rendue telle quelle (-> `SyncError.server`).
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let expected = expected,
              challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let der = SecCertificateCopyData(leaf) as Data
        let fp = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
        if fp == expected {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

/// Transport URLSession, avec épinglage optionnel du certificat par empreinte SHA-256 (DER).
public final class URLSessionTransport: Web3CTransport, @unchecked Sendable {
    private let session: URLSession
    private let configError: SyncError?

    /// Une empreinte non vide mais invalide ne désactive PAS l'épinglage : toute requête échoue avec `SyncError.invalid`.
    public init(tlsFingerprint: String? = nil) {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30
        cfg.httpCookieStorage = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        let expected = tlsFingerprint.flatMap(normalizeFingerprint)
        if let f = tlsFingerprint, !f.isEmpty, expected == nil {
            configError = .invalid("invalid TLS fingerprint")
        } else {
            configError = nil
        }
        session = URLSession(configuration: cfg, delegate: PinningDelegate(expected: expected), delegateQueue: nil)
    }

    deinit { session.finishTasksAndInvalidate() }

    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        if let e = configError { throw e }
        do {
            let (d, r) = try await session.data(for: request)
            guard let h = r as? HTTPURLResponse else { throw SyncError.transport("not an HTTP response") }
            return (d, h)
        } catch let e as SyncError { throw e }
        catch is CancellationError { throw CancellationError() }
        catch let e as URLError where e.code == .cancelled { throw CancellationError() }
        catch { throw SyncError.transport(error.localizedDescription) }
    }

    public func lines(for request: URLRequest) async throws -> (HTTPURLResponse, AsyncThrowingStream<String, Error>) {
        if let e = configError { throw e }
        let (bytes, r) = try await session.bytes(for: request)
        guard let h = r as? HTTPURLResponse else { throw SyncError.transport("not an HTTP response") }
        let stream = AsyncThrowingStream<String, Error> { cont in
            let task = Task {
                var buf = [UInt8]()
                do {
                    for try await b in bytes {
                        if b == 0x0A {
                            if buf.last == 0x0D { buf.removeLast() }
                            cont.yield(String(decoding: buf, as: UTF8.self))
                            buf.removeAll(keepingCapacity: true)
                        } else {
                            buf.append(b)
                        }
                    }
                    cont.finish()
                } catch {
                    cont.finish(throwing: error)
                }
            }
            cont.onTermination = { _ in task.cancel() }
        }
        return (h, stream)
    }
}
