# web3c_sync_engine (Dart)

Briques **génériques** communes aux moteurs de synchro bâtis sur le coffre chiffré
`web3c-sync` (`../../spec/PROTOCOL.md`) : VxIPTV / module IPTV d'AICompanion
(`vxiptv_sync`) et SoSimpleBank (`budget_sync_web3c`). Dart pur (pas de Flutter, pas de plugin) :
`dart test` suffit. Dépendances : `web3c_sync` (client de référence), `crypto`, `http`,
et `hive_ce` **uniquement** pour `lib/hive.dart`.

Ce n'est pas un framework de synchro : le moteur d'une appli (comment lire son stockage local,
quoi envoyer, comment appliquer un document reçu) reste dans l'appli. Le paquet porte ce qui est
identique d'une appli à l'autre et que l'on ne doit pas réécrire (ni re-relire) trois fois.

## Contenu

| Entry point | Contenu |
|---|---|
| `package:web3c_sync_engine/web3c_sync_engine.dart` | le cœur (ci-dessous) |
| `package:web3c_sync_engine/testing.dart` | `MemoryVaultTransport` / `MemoryVault` (+ `forgeTombstone`, `replay`, `rewindSeq` pour jouer un serveur malveillant) |
| `package:web3c_sync_engine/hive.dart` | `HiveSyncKeyValueStore` : `SyncKeyValueStore` sur une boîte Hive `Box<String>` (le seul fichier qui importe Hive) |

Le cœur :

- **`VaultTransport`** (+ `VaultRecord`, `VaultChange` = `VaultPut` / `VaultDelete` / `VaultRolledBack` /
  `VaultUndecryptable`, `VaultChanges`, `VaultPutResult`, `VaultDeleteResult`) : ce que le moteur attend d'un
  coffre. `Web3CVaultTransport` en est l'implémentation sur `Web3CSyncClient` : écritures optimistes
  (`If-Match`), `c = max(connu, distant) + 1`, suppression = marqueur chiffré `del:true` (jamais un `DELETE`
  serveur), tombstone serveur remonté en `VaultDelete` (non authentifié : à ignorer). **`close()` ne ferme
  pas le client HTTP** : il appartient au contrôleur de groupe, qui survit au moteur.
- **Fusion** (`lww.dart`) : `localWins(Versioned, Versioned)` (le `u` le plus récent gagne ; à égalité la
  charge utile canonique la plus grande, IPTV-DATA §3), `canonicalJson`, `payloadHash`.
- **Persistance de la comptabilité** (`SyncMetaStore` sur une interface `SyncKeyValueStore`
  de 7 méthodes) : version connue de chaque document (`SyncMeta` : `u`, `seq`, supprimé ?, synchronisé ?,
  empreinte de la charge utile), index docId -> (collection, clé), **curseur** persistant, **plus grand
  `next` jamais vu** (`highWater`), **plancher de compteur `c` par document** (anti-rollback, `counterFloor`
  à brancher sur le client), **boîte d'envoi** (`OutboxEntry` : une entrée par document, échéance `due`
  = debounce / backoff, `tries`, **sans charge utile** : elle est reconstruite depuis l'état local à l'envoi),
  réglages de l'appli (`setting`/`setSetting`, conservés par `reset`). Aucun secret.
- **`screenPage(page, meta)`** : le tri anti-rollback d'une page de `changes` avant de rien appliquer
  (flux sous le plus grand `next` vu = `RollbackException` ; document sous son plancher `c` = rejeu, jamais
  appliqué ; compteurs des autres mémorisés ; tombstones serveur et illisibles mis de côté). Le curseur
  (`setCursor` / `noteHighWater`) est avancé par l'appelant après application.
- **Secrets** : `SyncSecretStore` (3 méthodes, à brancher sur Keychain/Keystore), `MemorySyncSecretStore`,
  `SyncSecretKeys(prefix)` (noms des entrées d'un appairage, sous un préfixe propre à l'appli),
  `SecretStoreDeviceKeyStore` (clé d'appareil Ed25519 dans le coffre sécurisé).
- **`SyncGroupController`** : créer / lien d'appairage / rejoindre / membres / révoquer / quitter / purger /
  `load` / `forgetLocally`, paramétré par l'instance (`iptv`, `banking`, `aiteam`) et l'URL par défaut ;
  possède le `Web3CSyncClient`. Dart pur : pas de `ChangeNotifier`, un callback `onChanged`.
  **Erreurs assainies** : `error` et l'exception levée (`SyncEngineException`) ne contiennent que
  `describeSyncError(e)`.
- **Erreurs** : `SyncEngineException`, `describeSyncError` (jamais de lien d'appairage, de clé, d'URL ni
  d'hôte : `FormatException.toString()` imprime la source, `ArgumentError.value` la valeur,
  `SocketException` l'hôte), `isRetryableSyncError`, `retryAfterOf`, `backoffDelay` (exponentiel plafonné,
  `Retry-After` prioritaire).

## Brancher une appli

```dart
// 1. Secrets : 3 méthodes sur le plugin de l'appli.
class MySecrets implements SyncSecretStore { /* read / write / delete */ }

// 2. Comptabilité : une boîte Hive (ou tout SyncKeyValueStore), après l'init Hive de l'appli.
final meta = SyncMetaStore(() => HiveSyncKeyValueStore.open('myapp_sync_meta'));
await meta.init();

// 3. Groupe : instance serveur + préfixe des entrées de coffre.
final group = SyncGroupController(
  secrets: MySecrets(), keys: const SyncSecretKeys('myapp.web3c.'),
  instance: 'banking', defaultServerUrl: 'https://sync-banking.web3c.cc',
  onChanged: notifyListeners, // dans un ChangeNotifier d'UI qui enveloppe le contrôleur
)..counterFloor = meta.counterFloor; // AVANT load()/join()/createGroup()
await group.load();

// 4. Transport + moteur de l'appli.
final transport = Web3CVaultTransport(group.client!);   // ne ferme pas le client
final page = await transport.changes(meta.cursor);
final s = await screenPage(page, meta);                 // throws RollbackException si le flux recule
for (final p in s.accepted) { /* appliquer p.record : fusion avec localWins, marqueurs deleted */ }
await meta.setCursor(page.next);
await meta.noteHighWater(page.next);
// ... et pour envoyer : transport.put/delete(..., knownSeq: m?.seq, knownCounter: meta.counterFloor(c, docId) ?? 0),
//     puis meta.noteCounter(c, docId, res.record.counter) et meta.setEntry(...)
```

Les deux consommateurs (`vxiptv_sync/lib/src/group_controller.dart`, `budget_sync_web3c/lib/src/group_controller.dart`)
sont de minces `ChangeNotifier` qui délèguent à `SyncGroupController` ; leurs `SyncMetaStore` / `BudgetSyncMetaStore`
sont des sous-classes d'une ligne qui ouvrent leur boîte Hive.

## Points d'extension (ce que l'appli garde)

- **Le moteur** : quoi surveiller localement, comment fabriquer la charge utile d'un document, comment
  appliquer un document reçu, ordre des collections (IPTV : un profil avant ses enfants), cascade de
  suppressions. Les moteurs IPTV (`IptvSyncEngine`) et budget (`Web3CBudgetSync`) ont des machines à états
  voisines mais pas identiques (backoff global vs par entrée, sondage de secours, état `connecting`, statut
  non fatal ou fatal sur un document refusé...) : les unifier changerait leur comportement observable, ils
  restent chez eux. Les règles de fusion normatives (IPTV-DATA §3 : « le serveur fait foi sans modification
  locale en attente », marqueur contre `u` local, résurrection) sont appliquées par chacun avec `localWins`.
- **Emplacements de domaine de `SyncMeta`** : `l` (clé locale si elle diffère de la clé logique) et `x`
  (liste opaque de chaînes) ne sont sérialisés que s'ils sont renseignés (IPTV les utilise, le budget non).
- **Stockage** : toute implémentation de `SyncKeyValueStore`. **Secrets** : toute implémentation de
  `SyncSecretStore`. L'implémentation `flutter_secure_storage` n'est volontairement pas ici : elle ferait du
  paquet un paquet Flutter (plus de `dart test`) ; elle tient en 12 lignes (voir `vxiptv_sync/lib/secure_store.dart`).
- **Langue des messages** : `describeSyncError` est en anglais. Une appli qui veut ses propres phrases (c'est
  le cas d'AICompanion, voir ci-dessous) écrit sa fonction ; la règle (jamais de secret dans un message) est
  la même.

## Format persistant (stable : c'est celui des appareils déjà installés)

Une boîte de chaînes. `m/{collection}/{k}` : `{"u","seq","deleted","synced"[,"h"][,"l"][,"x"]}` ;
`i/{docId}` : `{collection}/{k}` ; `o/{collection}/{k}` : `{"c","k","u","del","due","n"}` ;
`c/{collection}/{docId}` : plus grand `c` vu ; `cursor` ; `hw` ; `set/{nom}` : réglages (survivent à `reset`).
Les noms d'entrées de secrets sont `{préfixe}server|groupId|groupKey|deviceSeed|adminToken|tlsFingerprint|isOwner`.
`test/meta_store_test.dart` fige cette disposition.

## AICompanion

`the_ai_team/lib/services/cloud/web3c/` n'utilise pas ce paquet (voir le rapport de l'extraction) : il
implémente `CloudProvider` (57 méthodes) directement sur `Web3CSyncClient`, avec une boîte d'envoi en
mémoire, des messages d'erreur en français, un `Web3CMetaStore` à valeurs entières et à portée par groupe
dans la boîte Hive `web3c_sync_meta` (format incompatible), et un merge `upsert` dont le départage
d'égalité diffère de `localWins`. Même protocole, mêmes garanties, autre code.

## Dépendance à `web3c_sync`

`pubspec.yaml` déclare `web3c_sync` en **git** (même url / ref / chemin que tous les consommateurs :
`ref: v0.1.0`, `path: clients/dart`) et non en `path: ../dart` : `pub` refuse deux sources différentes pour
un même nom de paquet, et les consommateurs gardent `web3c_sync` en git. Quand le dépôt sera tagué `v0.2.0`,
on pourra faire pointer ce `ref` (dans le moteur et dans chaque consommateur) vers `v0.2.0`.

## Tests

```sh
dart pub get
dart test                                  # unitaires (transport mémoire, fusion, comptabilité, secrets, erreurs, tri de page, contrôleur) ; intégration sautée sans WEB3C_SYNCD
WEB3C_SYNCD=/chemin/syncd dart test        # + deux appareils contre le vrai serveur Go
```

Build du serveur : `cd ../../server && go build -ldflags="-linkmode=external" -o /chemin/syncd ./cmd/syncd`
(sur macOS arm64, si le binaire est tué au lancement : `codesign -s - -f /chemin/syncd`).
Les tests de domaine (mapping IPTV, mapping budget, moteurs, sélecteur) restent dans `vxiptv_sync` et `budget_sync_web3c`.
