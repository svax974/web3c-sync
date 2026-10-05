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
let page = try await b.changesAll(since: cursor)           // items déchiffrés (+ marqueurs `deleted`), rejected, tombstones (à ignorer)
for try await ev in b.stream(since: page.next) { /* signal -> changes(since:) */ }

// Notes communautaires (routes publiques, PoW)
let c = CommunityClient(baseURL: url, powBits: 16)
try await c.vote(contentKey: "movie:tmdb:603", profileId: "p1", kUser: keys.rating, rating: 7.5)   // K_rating
```

## Sécurité (revue `../../spec/SECURITY-REVIEW.md`)

- **Compteur `c`** : tout plaintext porte `c` (entier >= 1) ; un document sans `c` est rejeté (`rejected`, erreur
  `SyncError.missingCounter` ; `getDoc` la lève) — pas de compatibilité ascendante. `upsert` écrit
  `c = max(c local connu, plancher, c distant) + 1` ; `putDoc(... counter:)` l'accepte explicitement (sinon
  `counterFloor + 1`). `u` est ramené à `now + 5 min` si besoin (`updatedAt` ; valeur brute dans `rawUpdatedAt`).
- **Anti-rollback** : `init(... counterFloor: { collection, docId in plusGrandCVu })` ; un document dont `c` est
  inférieur est mis dans `rejected` (`error == .rollback`), `getDoc` lève `.rollback`. `changes(since:)` lève `.rollback`
  si le serveur renvoie `next < since` ; `changesAll` s'arrête si le curseur ne progresse pas et est plafonnée par
  `maxPages` (1000). **La persistance du plancher et du plus grand `next`/`seq` est à la charge de l'app.**
- **Suppression** : `putMarker(collection:logicalId:updatedAt:counter:ifMatch:)` écrit `{"v":1,"u","c","k","del":true}` ;
  les lecteurs le voient comme un `SyncDocument` avec `deleted == true`. Les **tombstones créés par le serveur**
  (`deleteDoc`, `ChangesPage.tombstones`) **ne sont pas authentifiés** (`Tombstone.isAuthenticated == false`) : un moteur
  ne doit pas s'en servir pour supprimer un élément local, seulement les ignorer / les signaler.
- **Transport** : `http://` refusé hors loopback (`127.0.0.1`, `::1`, `localhost`) ; les redirections ne sont jamais
  suivies (une 3xx devient `SyncError.server`) ; une empreinte TLS non vide mais invalide fait échouer toutes les
  requêtes (`SyncError.invalid`, fail-closed ; `init(link:)` lève). Les inits non-`throws` ne changent pas : l'erreur est
  mémorisée et levée à la première requête.
- **Notes publiques** : `K_rating` (`DerivedKeys.rating`) remplace `K_id` pour les pseudonymes ; le vote porte `t`
  (secondes, `clock` injectable), inclus dans la preuve de travail. Un vote dont `t` n'est pas strictement postérieur au
  précédent du même pseudonyme reçoit 409 (`SyncError.conflict`) : deux votes dans la même seconde pour un même contenu
  échouent. `contentKey` doit valoir `^(movie|tv|series):tmdb:[0-9]{1,9}$` (`SyncError.invalid` sinon).

Épinglage TLS (serveur perso auto-signé) : `tlsFingerprint:` = SHA-256 du certificat DER (hex, avec ou sans `:`).
Transport injectable via `Web3CTransport` pour tester sans réseau.

## Tests

```
swift test                                   # vecteurs + crypto + durcissement (intégration sautée)
WEB3C_SYNCD=/chemin/syncd swift test         # + intégration contre le vrai serveur Go
```

Binaire serveur : `cd ../../server && go build -ldflags="-linkmode=external" -o /chemin/syncd ./cmd/syncd`
(sur macOS, ré-signer si le binaire est tué au lancement : `codesign -s - -f /chemin/syncd`).
