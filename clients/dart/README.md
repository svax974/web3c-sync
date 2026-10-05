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
final page = await client.changesAll(0);           // DocChange | Tombstone | Undecryptable
client.stream(page.next).listen((e) => /* changes(since) */ null);

final link = await client.createJoinLink();        // QR : web3c-link:v1?...&k=<K_g>
// autre appareil : GroupLink.parse(s) -> Web3CSyncClient(...).join(link.token, 'Apple TV')

final com = CommunityClient('https://sync.example.com', 16);
await com.vote('movie:tmdb:603', profileId, kUser, 7.5);   // pseudonyme + PoW
```

Erreurs typées : `ConflictException(currentSeq)`, `QuotaException`, `RateLimitedException`,
`UnauthorizedException`, `ForbiddenException`, `NotFoundException`, `GoneException(seq)`,
`ServerException`, `BadRequestException`, plus `DecryptException` / `IntegrityException`.

## Tests

```sh
dart pub get
dart test                                  # vecteurs + crypto + SSE ; intégration sautée sans WEB3C_SYNCD
WEB3C_SYNCD=/chemin/syncd dart test        # + intégration contre le vrai serveur Go
```

Build du serveur : `cd ../../server && go build -ldflags="-linkmode=external" -o /chemin/syncd ./cmd/syncd`
(sur macOS arm64, si le binaire est tué au lancement : `codesign -s - -f /chemin/syncd`).
