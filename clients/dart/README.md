# web3c_sync (Dart)

Client de référence du protocole web3c-sync v1 (`../../spec/PROTOCOL.md`). Dart pur, sans Flutter.
Dépendances : `cryptography`, `http`, `meta`.

```dart
final key = await DeviceKey.generate();            // à persister via un DeviceKeyStore (Keychain/Keystore)
final client = Web3CSyncClient(
  baseUrl: 'https://sync.example.com', instance: 'iptv', deviceKey: key,
  // tlsFingerprint: 'AB:CD:…'  // serveur auto-signé : épinglage SHA-256
);
await client.createGroup();                        // génère groupId et K_g si absents
await client.upsert('progress', 'movie_1', {'pos': 12}); // GET/PUT If-Match, fusion sur 409
final page = await client.changesAll(0);           // DocChange | Tombstone | Undecryptable | RolledBack
client.stream(page.next).listen((e) => /* changes(since) */ null);

final link = await client.createJoinLink();        // QR : web3c-link:v1?...&k=<K_g>
// autre appareil : GroupLink.parse(s) -> Web3CSyncClient(...).join(link.token, 'Apple TV')

final com = CommunityClient('https://sync.example.com', 16);
await com.vote('movie:tmdb:603', profileId, deriveKeys(kg).rating, 7.5);   // pseudonyme (K_rating) + PoW(t)
```

## Sécurité (revue du protocole)

- **Documents** : le clair est `{"v":1,"u","c","k","d"}` ; `c` (entier >= 1) est obligatoire, sans lui le document est
  `Undecryptable(InvalidDocumentException)`. `upsert` écrit `c = max(plancher local, c distant) + 1` ; `putDoc` /
  `putMarker` acceptent `counter:` (sinon calculé de la même façon).
- **Suppression** : `putMarker(...)` écrit un marqueur chiffré `del:true` ; il ressort en `DocChange` avec
  `deleted == true`. C'est le seul moyen authentifié de supprimer.
- **Tombstones serveur** (`Tombstone`, `deleteDoc`) : **non authentifiés** (`isAuthenticated == false`). Un moteur
  de synchro doit les ignorer (au plus les signaler) : le serveur peut en forger.
- **Anti-rollback** : `counterFloor: (collection, docId) => plusGrandCVu` au constructeur. Un document dont `c` est
  inférieur au plancher sort en `RolledBack` (`changes`) ou `RollbackException` (`getDoc`, `upsert`). `changes(since)`
  lève `RollbackException` si `next < since`. La mémoire des planchers et des curseurs est à la charge de l'appelant.
- **`u`** : `updatedAt` est plafonné à maintenant + 5 min ; la valeur brute est dans `rawUpdatedAt`.
- **`changesAll`** s'arrête si `next` ne progresse pas et lève `ServerException` après `maxPages` (10 000).
- **Transport** : `http://` refusé hors boucle locale (`ArgumentError`) ; redirections jamais suivies (3xx =
  `ServerException`). `tlsFingerprint` épingle le certificat **feuille** (SHA-256 du DER, hex ou base64url), sans
  autorité de certification ni vérification du nom d'hôte : il faut le renouveler avec le certificat. Une empreinte mal
  formée lève `FormatException` à la construction (échec fermé).
- **Notes publiques** : `t` (secondes, horloge injectable `clock:`) est dans le corps et dans la preuve de travail ;
  `powDigest/powOk/solvePow/solvePowAsync` exigent `t:`. Un vote dont `t` n'est pas strictement postérieur au
  précédent du même pseudonyme donne `ConflictException` (409). `contentKey` : `^(movie|tv|series):tmdb:[0-9]{1,9}$`.

Erreurs typées : `ConflictException(currentSeq)`, `QuotaException`, `RateLimitedException`,
`UnauthorizedException`, `ForbiddenException`, `NotFoundException`, `GoneException(seq)`,
`ServerException`, `BadRequestException`, plus `DecryptException` / `IntegrityException` /
`InvalidDocumentException` / `RollbackException`.

## Tests

```sh
dart pub get
dart test                                  # vecteurs + crypto + SSE ; intégration sautée sans WEB3C_SYNCD
WEB3C_SYNCD=/chemin/syncd dart test        # + intégration contre le vrai serveur Go
```

Build du serveur : `cd ../../server && go build -ldflags="-linkmode=external" -o /chemin/syncd ./cmd/syncd`
(sur macOS arm64, si le binaire est tué au lancement : `codesign -s - -f /chemin/syncd`).
