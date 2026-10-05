# Revue de sécurité adversariale — web3c-sync v1

Date : 2026-10-05. Périmètre : `spec/PROTOCOL.md`, `spec/IPTV-DATA.md`, `server/` (Go),
`clients/dart`, `clients/swift`. Revue en lecture seule du dépôt ; les preuves ont été
produites par des tests Go jetables dans un **copie** du module
(`/private/tmp/claude-501/-Users-steph-Dev-Apps-vxiptv-workspace/1e26ccf8-60dc-49ae-9551-e68fcd532bf9/scratchpad/review/server/internal/api/sec*_test.go`,
lancés par `go test -ldflags=-linkmode=external ./internal/api -run TestSec -v`).
Rien n'a été modifié dans le dépôt hormis ce fichier.

## 1. Modèle de menace

| Adversaire | Capacités supposées |
|---|---|
| Attaquant réseau passif/actif (TLS en place) | Voit/rejoue ce que le TLS laisse passer côté proxy ; sans TLS (serveur perso mal configuré) : tout. Peut ouvrir des milliers de connexions, forger des clés Ed25519 jetables. |
| Anonyme Internet | Peut créer des groupes (hors jeton admin), voter (notes publiques), signer avec n'importe quelle clé. |
| Utilisateur malveillant (autre groupe) | Possède un groupe valide (créé gratuitement, devient propriétaire), donc peut émettre des jetons, des membres, des documents, des blobs, des flux SSE. |
| Membre malveillant / appareil compromis du même groupe | Connaît `K_g` : peut lire/écrire/supprimer tout le groupe (inhérent au modèle). |
| Appareil révoqué | Connaît `K_g` à jamais (pas de rotation, §8 du protocole) ; n'a plus accès au serveur, en théorie. |
| Opérateur curieux ou compromis | Voit la base, le disque, le trafic en clair derrière le proxy, IP, horodatages. Ne connaît pas `K_g`. Peut modifier la base, servir des réponses arbitraires. |

Propriétés visées : (P1) le serveur ne voit jamais de donnée en clair ; (P2) `K_g` ne transite pas ;
(P3) isolation entre groupes ; (P4) révocation immédiate ; (P5) l'opérateur ne peut pas altérer sans détection
(propriété du plan, **non** promise par `PROTOCOL.md` §0, qui ne promet que la confidentialité).

## 2. Résumé exécutif

La cryptographie de base est saine : AES-256-GCM avec AAD liée à `instance/groupe/collection/docId`,
HKDF correct, HMAC de docId à encodage préfixé par la longueur (pas de collision collection/id),
signature des requêtes qui couvre méthode, chemin+requête brut, horodatage, nonce, hash du corps et instance,
vérification `HMAC(k)==docId` côté Dart et Swift, isolation inter-groupes correcte, jeton de jointure
haché à usage unique et atomique, aucune injection SQL, aucune traversée de chemin pour les blobs.

Les défauts réels se situent dans la **résistance au déni de service**, la **tenue de la révocation sur SSE**,
la **comptabilité des quotas pour les blobs**, la **limitation de débit par IP** et surtout dans l'**écart entre la
propriété P5 et la réalité** : un opérateur malveillant peut supprimer, ressusciter, rejouer d'anciennes
versions et présenter des vues différentes à chaque appareil, sans qu'aucun client ne puisse le détecter.

Constats confirmés (reproduits) : 1 haute-DoS pré-authentification, 1 haute-DoS cache de nonces, 1 haute-révocation SSE,
plusieurs moyennes (quota blob, amplification SSE/changes, croissance non bornée, votes, purge par inactivité),
quelques faibles. Voir §3 et le tableau §6.

## 3. Constats CONFIRMÉS (reproduits)

### C1 — Haute — Le corps de requête est lu intégralement AVANT toute authentification (DoS mémoire anonyme)
- Emplacement : `server/internal/api/api.go:130-141` (`signed`), routes `PUT /v1/g/{gid}/b/{blob}` (`api.go:80`, limite `MaxBlobSize+64` = 16 Mio) et `PUT …/d/…` (256 Kio).
- Scénario : un anonyme, sans clé ni en-tête, envoie `PUT /v1/g/x/b/y` avec `Content-Length: 16777280`
  et n'envoie que 12 Mio (ou goutte à goutte). Le serveur fait `io.ReadAll` (doublement de tampon) avant de vérifier
  la signature : ~14 Mio de tas par connexion tenue jusqu'au `ReadTimeout` de 60 s. 1 000 connexions ≈ 14 Go.
- Preuve : `TestSecPreAuthBodyBuffering` :
  `20 unauthenticated stalled PUT /b (12 MiB sent each, no X-Signature): heap in use grew by 277 MiB (HeapInuse 3 -> 281 MiB)`.
- Correctif : (1) refuser avant lecture si un en-tête d'authentification manque/est mal formé, si l'horodatage est hors fenêtre ou si
  `Content-Length` dépasse la limite ; (2) vérifier l'appartenance au groupe (lookup SQLite par `X-Device` brut, sans la signature)
  avant de lire un corps > 4 Kio, puis hacher en flux (`io.TeeReader` vers `sha256`) avec `MaxBytesReader`, et vérifier la signature
  à la fin ; (3) limiter globalement les connexions (`netutil.LimitListener`) et les requêtes en vol par IP.

### C2 — Haute — Le cache de nonces est alimenté par n'importe quelle clé, sans appartenance ni limite, et n'est balayé que toutes les heures
- Emplacement : `api.go:171-201` (nonce enregistré dès que la signature est valide, **avant** le contrôle d'appartenance), `support.go:87-113`, balayage `api.go:701` (ticker d'une heure, TTL 5 min).
- Scénario : un anonyme génère des clés Ed25519 jetables et signe `GET /v1/g/<n'importe quoi>/info` en boucle : chaque requête (403)
  ajoute une entrée `pub|nonce` (~100-150 o) qui reste jusqu'à 1 h. À 10 000 req/s : ~36 M d'entrées/h (> 4 Go). Il n'existe aucune limite par IP
  hors création de groupe, écritures et notes.
- Preuve : `TestSecNonceCacheGrowth` : `nonce cache entries after 3000 non-member requests: 3000 (swept hourly only)`.
- Correctif : borner la taille (éviction LRU/`maxEntries`, refus 503 au-delà) ; balayer à chaque minute ; ne mémoriser le nonce qu'après le
  contrôle d'appartenance ; ajouter une limite par IP avant vérification de signature (token bucket par /64 IPv6 ou /32 IPv4) ; clé du cache sur les octets
  décodés de la clé publique (voir C8).

### C3 — Moyenne — Un appareil révoqué (ou un groupe purgé) continue de recevoir les événements SSE
- Emplacement : `api.go:474-538` (`stream`) : l'appartenance n'est vérifiée qu'à l'ouverture ; aucune re-vérification, ni sur `ping`, ni sur événement ; `removeMember` (`api.go:306`) et `purge` ne ferment pas les abonnés.
- Scénario : l'appareil volé ouvre un flux, le propriétaire le révoque (204, et les requêtes REST donnent 403). Le flux reste ouvert indéfiniment
  (ping toutes les 25 s) et continue de livrer `collection`, `docId`, `seq`, `deleted` de chaque écriture : activité de visionnage en temps réel, volumes, fréquence.
  Le contenu reste chiffré, mais P4 (« révocation immédiate ») est violée.
- Preuve : `TestSecRevokedSSE` : `REVOKED DEVICE STREAM RECEIVED: data: {"collection":"progress","docId":"BwcH…","seq":1,"deleted":false}` après un 204 de révocation et un 403 sur `/info`.
- Correctif : le hub garde `(gid, pub)` par abonné ; `removeMember`/`purge`/expiration appellent `hub.kick(gid, pub)` qui ferme le canal (le handler retourne). En plus,
  vérifier `IsMember` toutes les N minutes dans la boucle du ticker. Ajouter un plafond de durée de flux (ex. 1 h, le client se reconnecte).

### C4 — Moyenne — Contournement du quota d'octets par PUT de blob concurrents (comptabilité ≠ disque)
- Emplacement : `store/store.go:402-432` (`PutBlob`) : la transaction SQL (taille comptabilisée) est validée, puis `os.WriteFile` est fait **hors transaction et sans verrou** ; deux PUT du même `blobId` s'entrelacent.
- Scénario : un membre envoie en parallèle un blob de 16 Mio et un de 1 octet avec le même id ; la ligne SQL/compteur retient la dernière transaction (1 o) tandis que le fichier fait 16 Mio. Répété sur des milliers d'ids : occupation disque arbitraire au-delà de `MaxBytes` (64 Mio), invisible dans `/info`. Au passage, un lecteur peut aussi voir un fichier partiellement écrit.
- Preuve : `TestSecBlobRace` (20 PUT concurrents, tailles 1-20 Kio, 30 tours) : `mismatching rounds: 6/30`, ex. `db size=6000 accounted=6000 file=14000`, `db size=4000 accounted=4000 file=12000`.
- Correctif : écrire dans un fichier temporaire (`id.tmp.<rand>`) dans le même répertoire, `fsync`, puis `rename` atomique **à l'intérieur** de la section sérialisée (mutex par `(gid,id)` ou faire le rename avant le `Commit` et annuler en cas d'échec) ; compter la taille réelle (`Stat`) ; réconcilier au démarrage. Même problème de durabilité pour `DeleteBlob` (fichier supprimé avant commit, `store.go:460`) et `PurgeGroup` (ligne puis fichiers, `store.go:239-244` : un PutBlob concurrent recrée un dossier orphelin).

### C5 — Moyenne — Croissance non bornée de la base par tombstones, blobs minuscules, jetons et membres
- Emplacement : `store.go:343-374` (tombstone : `docs` décrémenté, la ligne reste « pour la vie du groupe », `store.go:312` ne compte que les docs vivants) ; `store.go:402-423` (aucun plafond du nombre de blobs) ; `api.go:255-268` (aucun plafond ni limite de débit sur `join-tokens`) ; `store.go:169` (aucun plafond de membres).
- Scénario : sur une instance publique, n'importe qui crée un groupe (devient propriétaire). En boucle : PUT puis DELETE d'ids neufs → `docs=0` mais des lignes s'accumulent ; blobs de 1 octet (un inode de 4 Kio chacun pour 64 M blobs théoriques) ; émission illimitée de jetons ; membres illimités avec des clés jetables. Chaque tombstone est aussi renvoyé à jamais par `changes?since=0` (coût de resynchronisation pour les vrais appareils du groupe).
- Preuve : `TestSecTombstoneGrowth` (maxDocs=5, 300 créations+suppressions) : `info … "docs":0,"bytes":0 … "seq":600` et `rows in docs table: 300` ; `TestSecBlobCount` : 500 blobs d'1 octet acceptés (`"bytes":500`, `maxBytes 65536`).
- Correctif : plafond de lignes totales par groupe (vivantes + tombstones, ex. 2× `MaxDocs`), purge des tombstones plus vieux que N jours (documenter le compromis résurrection), plafond du nombre de blobs et comptabilisation d'un coût minimal par blob (≥ 4 Kio), plafond de jetons actifs (ex. 5) et de membres (ex. 50) par groupe, quotas globaux par instance.

### C6 — Moyenne — Amplification de charge : flux SSE illimités, `since=0` relit toutes les enveloppes, aucun `WriteTimeout`
- Emplacement : `api.go:474-538` + `store.go:377-396` (`Changes` sélectionne la colonne `env` même pour SSE qui n'émet que des signaux) ; `cmd/syncd/main.go:35-41` (pas de `WriteTimeout`) ; aucun plafond de flux par appareil ; `MaxOpenConns(1)` (`store.go:52`).
- Scénario : un membre (groupe de 64 Mio à 240 docs de 256 Kio) ouvre/ferme en boucle `stream?since=0` : chaque connexion relit ~64 Mio via l'unique connexion SQLite, ce qui sérialise **tout** le service. Un `changes?since=0` renvoie ~80 Mio de JSON, retenu en mémoire pendant toute la durée d'un client lent (pas de timeout d'écriture). 300 flux simultanés avec une seule clé sont acceptés.
- Preuve : `TestSecAmplification` : `/info` de base `216µs`, `changes?since=0` = `80 MiB`, avec 8 boucles SSE : pire latence `/info` = `119 ms` (×550) et `HeapSys=518 MiB` ; `TestSecSSEUnlimited` : `sseClients gauge with 1 device: 300`.
- Correctif : requête SSE/rattrapage sans la colonne `env` (`SELECT … length(env)` ou table `changes` séparée) ; plafond de flux par appareil (3) et par groupe (20) ; `WriteTimeout`/`http.ResponseController.SetWriteDeadline` glissant (et pas de deadline nulle) ; limiter `changes` en octets (≤ 4 Mio par page, pas seulement 500 items) ; limite de débit des lectures par appareil.

### C7 — Moyenne — Notes communautaires : PoW sans effet réel, rejeu d'un ancien vote, aucun plafond de stockage
- Emplacement : `api.go:596-635`, `proto/proto.go:193-228`, `support.go:187-198`.
- Scénario : (a) le PoW de 16 bits coûte ~15 ms (précalculable hors ligne, il ne dépend d'aucun défi serveur) ; un même client vote N fois avec N pseudonymes aléatoires (aucun lien pseudonyme ↔ appareil) : le seul frein est la limite de 30 votes/min **par IP** (cf. C9). (b) un vote capturé (par le proxy, un journal, un opérateur) peut être rejoué plus tard et **écrase** le vote plus récent du même pseudonyme (pas d'horodatage ni de compteur dans la charge). (c) la table `ratings` et l'espace des `contentKey` (`[a-z0-9:_.-]{1,128}`) sont illimités : stockage gratuit et pollution.
- Preuve : `TestSecVoteStuffing` : `200 votes with 200 random pseudonyms at 16-bit PoW: accepted=200 in 3.64s; aggregate={"count":200,"sum":2000,"avg":10}` ; `replay of captured older vote (r=2) after r=9: status=204 aggregate={"count":1,"sum":2,"avg":2}`.
- Correctif : défi serveur (`GET /v1/public/challenge` → `salt` signé HMAC + expiration 5 min, à inclure dans le PoW), coût adaptatif (≥ 22 bits ou Argon2/scrypt court) ; intégrer un `ts` ou numéro de version croissant dans le vote et refuser un `ts` ≤ au stocké ; plafonner les votes par contenu et les clés de contenu inconnues (liste TMDB/whitelist ou préfixes `movie:tmdb:`) ; rapport `count` pondéré/winsorisé. Honnêtement, une note publique anonyme n'est pas à l'abri du bourrage ; documenter cette limite dans le protocole.

### C8 — Faible — Clé d'appareil en base64url non canonique : plusieurs identités pour une même clé, cache de nonces contourné
- Emplacement : `api.go:176-178` (décodage laxiste, la chaîne brute est renvoyée en `api.go:200` et utilisée pour l'appartenance, les limiteurs et la clé du cache de nonces `api.go:197`) ; `proto.UnB64` n'utilise pas `Strict()`.
- Scénario : les 3 derniers caractères possibles (bits de bourrage) donnent 4 encodages d'une même clé. (a) une clé peut se joindre trois fois de plus avec 3 jetons : le propriétaire voit 4 « appareils » ; en révoquer un ne coupe pas les autres (persistance après révocation si l'appareil a obtenu plusieurs jetons) ; (b) un même nonce rejoué avec un `X-Device` variant n'est pas détecté par le cache (le test montre 403 car le variant n'est pas membre, mais une route `modeSigned` — `join`, création — l'accepterait).
- Preuve : `TestSecNonCanonicalDevice` : `same nonce: orig=200 replay=401 replay-with-variant-device=403` ; les 3 `join` avec variantes → `200` ; `members` liste 4 lignes pour 1 clé (`…CQc`, `…CQd`, `…CQe`, `…CQf`).
- Correctif : après décodage, exiger `B64(pub) == X-Device` (comme pour `validGroupID`), ou utiliser `B64(pub)` canonique partout ; dans le cache de nonces, utiliser les octets décodés.

### C9 — Moyenne — Limitation de débit par IP contournable (en-tête de proxy, IPv6) et sans plafond global
- Emplacement : `support.go:187-198` (`clientIP`), `api.go:232` (création), `597` (votes), `638` (lectures).
- Scénario : (a) avec `SYNC_TRUST_PROXY=true`, la valeur de `X-Real-IP` est prise telle quelle, sans validation (`net.ParseIP`) : si le proxy ne l'écrase pas (Caddy `reverse_proxy` ne le fait pas par défaut ; nginx avec `proxy_set_header X-Real-IP $remote_addr` le fait), un client choisit sa propre « IP » et contourne création de groupe (20/jour), votes (30/min) et lectures. Il peut aussi inonder le dictionnaire des limiteurs avec des clés de 1 Mio (balayage horaire). (b) La clé est l'adresse IPv6 complète : un /64 offre 2^64 « IP ». (c) Sans `TRUST_PROXY` derrière un proxy, tous les utilisateurs partagent la même IP : 20 créations de groupe par jour et 30 votes/minute pour **tout** le monde (autodéni de service).
- Preuve : `TestSecIPSpoofAndAdminBrute` : `20 creations with CreatesPerDay=2 and spoofed X-Real-IP: 20 created` contre `5 creations, same (unspoofed) IP: 2 created`. (b) non reproduit (nécessite un réseau IPv6 routé), raisonnement par lecture du code.
- Correctif : valider avec `net.ParseIP`, normaliser IPv6 au /64 (et IPv4 mappées), n'accepter l'en-tête que si `RemoteAddr` ∈ liste de proxys de confiance (`SYNC_TRUSTED_PROXIES`), préférer le dernier saut de `X-Forwarded-For`, plafonner la taille de la clé et du dictionnaire ; ajouter des quotas globaux (groupes/jour/instance, octets totaux) ; refuser de démarrer sur une adresse non-loopback sans `SYNC_ADMIN_TOKEN_SHA256` ni `SYNC_OPEN_REGISTRATION=true`.

### C10 — Moyenne — Purge d'inactivité fondée uniquement sur les écritures : un groupe lu quotidiennement est supprimé au bout de 365 jours
- Emplacement : `store.go:216` (`Touch` jamais appelé, `grep` vide) ; `last_activity` n'est mis à jour qu'en `PutDoc` (l.316), `DeleteDoc` (l.364), `PutBlob` (l.417) ; `Maintain` supprime (`api.go:706`).
- Scénario : une instance `banking` ou un second appareil de consultation qui ne fait que lire/pairer pendant un an voit son groupe, ses documents et ses membres supprimés sans préavis. Aucun avertissement n'est visible côté client à part `purgeAt` dans `/info`, qui est lui-même calculé sur la dernière écriture.
- Preuve : confirmé par lecture (`grep -rn "Touch(" server` → seule la définition). Non exécuté en temps réel (365 jours).
- Correctif : appeler `Touch` (à débit limité, ex. au plus 1 fois/jour/groupe) sur toute requête authentifiée réussie, y compris `info`, `changes`, `stream`, `join` ; avertir via `/info` (`purgeAt` recalculé).

### C11 — Faible — Le jeton admin peut être deviné en ligne sans limite
- Emplacement : `api.go:222-231` : le contrôle du jeton précède la limite de débit (`api.go:232`) ; aucun compteur d'échecs ; hash SHA-256 non salé (`config.go:69`).
- Scénario : sur un serveur personnel, un attaquant signe avec une clé jetable et essaie des jetons à des milliers/s. Un jeton court ou un mot de passe humain tombe. Le hash non salé fuit en clair s'il apparaît dans un fichier d'environnement exposé.
- Preuve : `TestSecIPSpoofAndAdminBrute` : `300 wrong admin tokens: map[403:300] (no throttling, no 429)`.
- Correctif : compter les échecs par IP (et globalement) avant la comparaison, délai exponentiel ; imposer ≥ 128 bits (générer le jeton, ne pas laisser l'utilisateur le choisir) ; comparer `HMAC(serverSecret, token)`.

### C12 — Faible — Événement SSE perdu possible (publication hors ordre / canal plein)
- Emplacement : `api.go:493-495` (`if e.Seq <= last { return true }`) et `support.go:151-160` (publication non bloquante, tampon 128, hors de la transaction).
- Scénario : deux écritures concurrentes valident les seq 5 et 6 ; la goroutine du seq 6 publie avant celle du seq 5 ; le flux émet 6 puis ignore 5. Un abonné lent perd silencieusement les événements en cas de canal plein. Les deux clients prennent l'événement comme un simple signal, donc la perte se corrige au prochain événement ou à un `changes`, mais un client qui ne ferait que `changes(since=ev.seq)` perdrait le document.
- Preuve : `TestSecSSELostEvents` (8 appareils × 150 écritures concurrentes) : `SSE events missed on a live connection: 1` sur 1 exécution sur 3 (0 sur les deux autres).
- Correctif : au lieu de filtrer par `e.Seq <= last`, relire `Changes(last)` à chaque signal (le signal ne sert que de réveil) ; en cas de canal plein, forcer la reconnexion du client ; documenter dans le protocole que le curseur de synchronisation est celui de `changes`, jamais celui du flux.

### C13 — Faible — Swift : une empreinte TLS mal formée désactive silencieusement l'épinglage
- Emplacement : `clients/swift/Sources/Web3CSync/Transport.swift:56` (`tlsFingerprint.flatMap(normalizeFingerprint)` donne `nil`) et `Transport.swift:27-32` (`expected == nil` → `.performDefaultHandling`).
- Scénario : un lien d'appairage altéré/tronqué (`f=` invalide) donne une session non épinglée qui retombe sur les autorités système, sans erreur. Le client Dart, lui, lève une `FormatException` (échec fermé). Pour un serveur auto-signé le fonctionnement échoue fermé ; pour un serveur à certificat public il y a rétrogradation silencieuse.
- Preuve : non exécuté (nécessite un hôte TLS) ; confirmé par lecture, `normalizeFingerprint("zz")` retourne `nil` par construction.
- Correctif : `init(tlsFingerprint:)` doit lancer si la chaîne est non vide et invalide ; rendre le delegate fail-closed.

### C14 — Faible — `changesAll` (Dart) peut boucler indéfiniment sur un serveur malveillant
- Emplacement : `clients/dart/lib/src/client.dart:543-554` : `if (p.next < next) break;` laisse passer `p.next == next` avec `more == true`. Swift (`Client.swift:377`) utilise `p.next <= cursor` : correct.
- Scénario : un serveur compromis répond `{"items":[],"next":<since>,"more":true}` : boucle infinie, consommation CPU/réseau/batterie ; pages illimitées en mémoire.
- Correctif : `if (p.next <= next) break;` plus plafond de pages/éléments.

## 4. Défauts de conception / spécification (confirmés par lecture ou par raisonnement)

### S1 — Haute (écart avec P5) — Un opérateur malveillant peut supprimer, ressusciter, faire reculer et équivoquer sans détection
Le chiffrement authentifie chaque enveloppe isolément (AAD : instance, groupe, collection, docId) mais **rien ne lie une enveloppe à une version, à l'ordre ni à l'état du groupe**, et les tombstones ne sont pas authentifiés (créés par le serveur, `store.go:370`).

| Attaque d'un serveur malveillant | Possible ? | Détectable par un client actuel ? |
|---|---|---|
| Forger un contenu inédit | Non (AEAD, il ignore `K_g`) | Oui (déchiffrement échoue / `Undecryptable`) |
| Échanger deux documents entre docId/collection/groupe/instance | Non (AAD + vérification `HMAC(k)==docId`, Dart `client.dart:432`, Swift `Client.swift:311`) | Oui |
| Rejouer une ancienne version valide d'un document (rollback) | Oui | **Non** (pas de compteur dans l'enveloppe ; `u` interne plus ancien perd contre la valeur locale seulement sur les appareils qui l'ont déjà vue) |
| Supprimer n'importe quel document (tombstone forgé, `X-Deleted`) | Oui | **Non** (aucune authentification de la suppression) |
| Ressusciter un document supprimé (remettre une ancienne enveloppe) | Oui | **Non** |
| Cacher une écriture à certains appareils (déni sélectif) / retarder | Oui | **Non** |
| Vues différentes par appareil, réordonnancement (équivocation) | Oui (`seq`, `changes`, `next` non authentifiés, pas de chaîne de hachage) | **Non** |
| Ignorer une révocation / ajouter une clé d'appareil à la liste des membres | Oui | Non (la liste des membres est une donnée serveur) ; il ne gagne cependant pas `K_g` |
| Accéder au contenu | Non | — |

Correctifs, du moins coûteux au plus complet : (1) chaque client mémorise le plus haut `seq` vu par groupe et refuse un `info.seq`/`next` qui décroît (détecte les rollbacks complets, pas sélectifs) ; (2) compteur par document **dans le plaintext chiffré** (`"c":n`, strictement croissant par `k`) et le client refuse `c` inférieur au dernier vu pour ce docId ; (3) tombstones authentifiés : la suppression est un `PUT` d'un document chiffré `{"v":1,"u":…,"k":…,"del":true}` plus la suppression serveur ; le tombstone brut sans doublon authentique est ignoré ; (4) journal signé par les appareils : chaque écriture porte `H(prev)` et une signature Ed25519 de l'appareil (clé de la liste de membres épinglée à l'appairage via le QR), ou un checkpoint périodique `_head` = signature de `Merkle(docId, seq, H(env))` ; deux appareils échangent le checkpoint (hors bande/à l'appairage) pour détecter l'équivocation.

### S2 — Moyenne — `IPTV-DATA.md` mélange secondes serveur et millisecondes `u` pour décider de la résurrection
`IPTV-DATA.md §Suppression` : « sauf si son `u` local est plus récent que le `updatedAt` du tombstone ». Or `updatedAt` des tombstones est l'horodatage **serveur en secondes** (`store.go:363`, `PROTOCOL §7`) et `u` est en **millisecondes**, fixé par le client. Comparés tels quels, `u` est toujours ≈ 1000× plus grand : la suppression ne se propage jamais (résurrection) ; converti naïvement, c'est le serveur (non authentifié) qui décide quelle écriture gagne. Correctif : spécifier la comparaison (`u_local > updatedAt*1000`) **et** rendre le tombstone authentifié (S1-3) afin que la date vienne d'un appareil, pas de l'opérateur.

### S3 — Moyenne — LWW sur `u` fourni par le client, sans borne
Spec §3 (et `lastWriteWins`, `client.dart:128`, `Client.swift:424`) : la valeur `u` la plus grande gagne. Un appareil dont l'horloge est en avance (ou un membre compromis) publie `u = année 3000` et ses données gagnent définitivement : aucun autre appareil ne peut l'écraser tant que sa propre horloge n'a pas dépassé cette date. Aucune borne côté clients. Correctif : rejeter/clamper `u > now + 5 min` à la réception, utiliser un compteur hybride (HLC) plutôt que l'horloge murale.

### S4 — Moyenne — Aucune rotation de clé : la révocation ne protège pas les données déjà synchronisées, et les secrets sont fortement concentrés
`PROTOCOL §8` l'admet. Conséquence concrète pour IPTV : `sources` (identifiants Xtream/M3U **en clair dans le plaintext**, chiffrés seulement par `K_g`) et le PIN parental sont lisibles par tout appareil ayant déjà été membre, même révoqué (il a gardé `K_g` et peut déchiffrer tout ce qu'il a ou qu'un opérateur lui fournit). Révoquer ne suffit donc pas : il faut aussi changer les mots de passe chez le fournisseur. Correctif : documenter explicitement dans l'UI ; prévoir l'époque (`e`) et le ré-chiffrement ; isoler les secrets (`sources.pass`) sous une clé secondaire dérivée de `K_g` et rotative par appareil.

### S5 — Faible — Autres écarts spec ↔ implémentation
- `PROTOCOL §5` dit « refuse (401) si … non membre », l'implémentation renvoie 403 (cohérent avec §11 mais pas avec §5).
- `PROTOCOL §7/§10` : un blob de `MaxBlobSize+1…+64` octets reçoit 429 `quota`, pas 413 (`store.go:403`).
- `_name` est une collection autorisée et réservée « par convention » : un membre peut y écrire des documents (inoffensif, clés différentes `K_enc` vs `K_name`).
- Les limites de `field()` (u16) sont imposées par les clients (Dart/Swift refusent > 65535) mais **pas** par le serveur Go (`proto.Field` tronque silencieusement) : sans conséquence tant que le serveur ne calcule pas de docId, mais à corriger pour qu'une implémentation tierce ne puisse pas créer d'ambiguïté de cadrage.
- La signature ne couvre ni l'hôte ni l'origine : une requête signée pour un serveur `iptv` A est valide sur un autre serveur `iptv` B pendant 120 s si l'appareil y est aussi membre (même groupe copié). Ajouter l'hôte à la chaîne canonique si deux serveurs peuvent partager un groupe.

## 5. Fuites de métadonnées et vie privée (à connaître ; hors correctif cryptographique)

1. Le serveur voit : nom de collection en clair, **docId stable** par élément logique (donc l'historique de modification de chaque film/chaîne), `seq`, horodatage de chaque écriture, taille approximative (Padmé : granularité de 8 à 32 octets pour 100 à 1 000 o, ce qui, avec `name`/`icon` dans la charge `progress`, permet un recoupement titre ↔ longueur).
2. La progression est écrite chaque minute pendant la lecture : l'opérateur voit **quand** et **combien de temps** un groupe regarde quelque chose, pour quel docId (stable), depuis quelle IP (journaux proxy 7 jours).
3. Corrélation notes publiques ↔ groupe : les votes (`sync-iptv.web3c.cc`, toujours) arrivent depuis la même IP et au même moment que les écritures `ratings` du groupe : l'opérateur de l'instance publique lie un groupe à des contenus précis, même pour les utilisateurs de serveur personnel. Le pseudonyme de note utilise `K_id` comme `docId` (même clé pour deux usages) : préférer une clé HKDF dédiée (`info="rating"`).
4. `X-Updated-At`, `mtime` des blobs (`http.ServeContent`) et `members.joinedAt` sont des horodatages serveur visibles du client et de l'opérateur.
5. SQLite sans `secure_delete` ni `VACUUM` : le chiffré d'un document « supprimé », ou d'un groupe purgé, reste dans les pages libres et le WAL. Pas de fuite en clair (E2E), mais l'« effacement » promis est une suppression logique.

## 6. Soupçons non reproduits (raisonnement)

- **Redirections HTTP côté clients** : Dart (`IOClient`) et Swift (`URLSession`) suivent les redirections par défaut. Un serveur/proxy malveillant peut rediriger `PUT/DELETE` (307/308) vers un autre hôte avec les en-têtes signés (valables 120 s) et, pour `createGroup`, l'en-tête `Authorization: Bearer <adminToken>` : selon la plate-forme, l'en-tête peut être transmis. À vérifier ; désactiver `followRedirects` / `willPerformHTTPRedirection`.
- **HTTP clair** : aucun client n'impose `https://` (ni `localhost`) ; le jeton admin et toutes les métadonnées passent alors en clair, et l'épinglage est sans objet. Correctif : refuser `http` hors loopback.
- **Épinglage sur certificat feuille** : un certificat Let's Encrypt (60-90 jours) casse l'épinglage à chaque renouvellement ; épingler le SPKI plus une empreinte de secours.
- **Système de fichiers insensible à la casse** (macOS/Windows pour serveur perso) : `groupId` et `blobId` différant seulement par la casse partagent le même fichier (`store.go:400`) ; un utilisateur connaissant l'id d'un autre groupe pourrait écraser ses blobs (E2E : pas de lecture). Normaliser en minuscules hex pour les chemins.
- **Calculs PoW côté UI** : Dart `solvePowAsync` cède tous les 2 000 tours ; ~65 000 hachages Dart purs à 16 bits (quelques secondes avec à-coups). Swift expose aussi `solvePow` bloquant (appeler la variante `Async`).
- **Cache de nonces en mémoire** : redémarrage du serveur = fenêtre de rejeu de 120 s (info).
- **`Content-Type`/charge JSON `Decode`** : `putVote` accepte des données après le premier objet JSON ; sans conséquence.
- **`metrics`** : non authentifié, `SYNC_METRICS_LISTEN` doit rester privé (documenter ; rien n'est exposé par défaut).

## 7. Ce qui est correct et vérifié

- Signature : couvre méthode, `RequestURI` brut, timestamp, nonce (exactement 16 octets, chaîne signée donc variantes de nonce rejetées), hash du corps, instance. Injection de `\n` impossible (Go refuse dans le chemin/méthode/en-têtes). Fenêtre ±120 s, rejeu détecté (test existant et `TestSecNonCanonicalDevice` : même nonce, même appareil → 401).
- Isolation : `gid` toujours repris du chemin, canonique (22 car., 16 octets) et vérifié contre l'appartenance de **ce** groupe ; docs/blobs interrogés sur `a.gid`. Aucun IDOR inter-groupes ni vertical (jeton/purge/révocation réservés au propriétaire ; le propriétaire n'est pas révocable).
- Jeton de jointure : 16 octets CSPRNG, SHA-256 stocké, `UPDATE … WHERE used=0 AND expires_at>?` atomique (une connexion), 403 uniforme pour inconnu/utilisé/expiré.
- SQL : 100 % de requêtes paramétrées ; chemins de blobs : `gid` b64url canonique, `blobId` `^[A-Za-z0-9_-]{1,64}$` (pas de `.` ni `/`) : pas de traversée.
- Comptabilité docs/octets : 3 000 opérations aléatoires PUT/DELETE/recréation sur un groupe à 8 docs/4 000 o : compteurs toujours égaux aux sommes des lignes, jamais négatifs ni au-dessus du quota (`TestSecAccounting`).
- SSE : le `ReadTimeout` de 60 s n'interrompt pas un flux (testé avec 3 s : événement reçu à t+5 s).
- Jeton admin : comparaison à temps constant sur les hashes (`api.go:226`) ; 403 uniformes ; erreurs génériques, pas de journal de requêtes ni de contenu.
- Crypto : nonces 96 bits CSPRNG (`crypto/rand`, `SecRandomCopyBytes`, `Random.secure`), au plus 2^32 messages sous la même clé sans souci pratique (120 écritures/min/appareil) ; HKDF sel fixe + `info` distincts ; Padmé/déchiffrement sans oracle de cause ; vecteurs identiques entre Go/Dart/Swift ; épinglage Dart (`withTrustedRoots:false`, comparaison à temps constant) correct ; Swift compare l'empreinte de la feuille (non secrète, comparaison non constante sans conséquence).
- Les clients n'écrasent pas de données locales sur échec de déchiffrement/intégrité : `Undecryptable` (Dart) et `rejected` (Swift) sont renvoyés à l'appelant, le curseur avance.

## 8. Tableau récapitulatif

| # | Gravité | Statut | Titre |
|---|---|---|---|
| C1 | Haute | Confirmé | Lecture du corps (16 Mio) avant authentification |
| C2 | Haute | Confirmé | Cache de nonces alimenté par toute clé, balayage horaire, pas de limite |
| S1 | Haute | Conception | Rollback, suppression, résurrection, équivocation non détectables (P5) |
| C3 | Moyenne | Confirmé | Appareil révoqué : flux SSE toujours actif |
| C4 | Moyenne | Confirmé | Quota d'octets contourné par PUT de blobs concurrents |
| C5 | Moyenne | Confirmé | Croissance non bornée (tombstones, blobs, jetons, membres) |
| C6 | Moyenne | Confirmé | Amplification : SSE illimités, `since=0` relit les enveloppes, pas de `WriteTimeout` |
| C7 | Moyenne | Confirmé | Notes publiques : PoW inutile, rejeu d'un ancien vote, stockage illimité |
| C9 | Moyenne | Confirmé (en-tête) / raisonnement (IPv6) | Limitation par IP contournable (`X-Real-IP`, IPv6), pas de plafond global |
| C10 | Moyenne | Confirmé (lecture) | Purge d'inactivité fondée sur les seules écritures |
| S2 | Moyenne | Spéc | secondes vs millisecondes dans la règle de suppression |
| S3 | Moyenne | Spéc | LWW sans borne de `u` |
| S4 | Moyenne | Spéc | Pas de rotation : secrets IPTV lisibles par un appareil révoqué |
| C8 | Faible | Confirmé | Clé d'appareil non canonique : identités multiples, nonce contourné |
| C11 | Faible | Confirmé | Jeton admin devinable en ligne sans limite |
| C12 | Faible | Confirmé | Événement SSE perdu (rare) |
| C13 | Faible | Lecture | Swift : empreinte invalide = épinglage désactivé |
| C14 | Faible | Lecture | Dart `changesAll` boucle infinie possible |
| S5 | Faible/Info | Spéc | 401/403, 413/429, `_name`, `Field` serveur, hôte non signé |
| §5, §6 | Info | — | Fuites de métadonnées, redirections, HTTP clair, pin feuille, FS insensible casse |
