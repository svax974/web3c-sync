# Web3CSync (Swift)

Client de référence du protocole **web3c-sync v1** (`../../spec/PROTOCOL.md`) pour tvOS 16+, iOS 16+, macOS 13+.
Aucune dépendance : CryptoKit, Foundation/URLSession, async/await.

```swift
// Dépôt
.package(path: "../web3c-sync/clients/swift")   // produit : Web3CSync
```

## Usage

```swift
let key = try keyStore.loadOrCreate()                      // DeviceKeyStore (Keychain à fournir par l'app)

// Appareil 1 : créer le groupe et un lien d'appairage
let a = Web3CSyncClient(baseURL: url, instance: "iptv", deviceKey: key)
try await a.createGroup()                                  // génère groupId et K_g
let link = try await a.makeLink(token: a.createJoinToken().token).format()   // à afficher en QR

// Appareil 2
let b = try Web3CSyncClient(link: GroupLink.parse(link), deviceKey: DeviceKey())
try await b.join(token: parsed.token, deviceName: "Apple TV salon")

// Documents chiffrés de bout en bout
try await a.putDoc(collection: "progress", logicalId: "movie_1", payload: ["pos": 120], updatedAt: nowMs, ifMatch: 0)
let r = try await b.upsert(collection: "progress", logicalId: "movie_1",
                           local: Candidate(payload: ["pos": 300], updatedAt: nowMs))   // le `u` le plus récent gagne
let page = try await b.changesAll(since: cursor)           // items déchiffrés + tombstones
for try await ev in b.stream(since: page.next) { /* signal -> changes(since:) */ }

// Notes communautaires (routes publiques, PoW)
let c = CommunityClient(baseURL: url, powBits: 16)
try await c.vote(contentKey: "movie:tmdb:603", profileId: "p1", kUser: kId, rating: 7.5)
```

Épinglage TLS (serveur perso auto-signé) : `tlsFingerprint:` = SHA-256 du certificat DER (hex, avec ou sans `:`).
Transport injectable via `Web3CTransport` pour tester sans réseau.

## Tests

```
swift test                                   # vecteurs + crypto (intégration sautée)
WEB3C_SYNCD=/chemin/syncd swift test         # + intégration contre le vrai serveur Go
```

Binaire serveur : `cd ../../server && go build -ldflags="-linkmode=external" -o /chemin/syncd ./cmd/syncd`
(sur macOS, ré-signer si le binaire est tué au lancement : `codesign -s - -f /chemin/syncd`).
