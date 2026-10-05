# web3c-sync — protocole v1

Statut : brouillon d'implémentation (2026-10-05). Source de vérité du format sur
le fil et du chiffrement. Tout client (Dart, Swift) et le serveur (Go) doivent
passer les vecteurs de `spec/vectors/v1.json`. Contexte et décisions :
`AICompanion/docs-project/plans/2026-10-05-sync-web3c-backends-design.md`.

## 0. Propriétés visées

- Le serveur ne voit jamais de donnée utilisateur en clair : seulement des blobs
  chiffrés, des identifiants pseudonymisés, des tailles approximatives, des
  horodatages de transport.
- La clé de groupe `K_g` ne transite jamais par un serveur.
- Pas de compte : des appareils (clés Ed25519) membres de groupes.
- Un serveur = une **instance** (`iptv`, `banking`, `aiteam`) : même code, trois
  déploiements. Le nom d'instance est lié cryptographiquement aux documents.

Hors périmètre du chiffrement : les **notes communautaires** (§9), en clair par
nature (agrégat entre inconnus).

## 1. Conventions

- Encodage binaire textuel : **base64url sans remplissage** (RFC 4648 §5).
- Entiers : big-endian. `u16(n)` = 2 octets. `||` = concaténation.
- Hachage / MAC : SHA-256, HMAC-SHA-256, HKDF-SHA-256 (RFC 5869).
- Signatures : Ed25519 (RFC 8032). Chiffrement : AES-256-GCM, nonce 96 bits
  aléatoire, tag 128 bits.
- `field(x)` = `u16(len(x)) || x` (champ préfixé par sa longueur, anti-ambiguïté).
- JSON : UTF-8, clés triées non requises (le JSON chiffré n'est pas canonique).

## 2. Identifiants et clés

| Nom | Définition |
|---|---|
| `groupId` | 16 octets aléatoires (CSPRNG), base64url (22 car.), choisis par le créateur. Public. |
| `K_g` | 32 octets aléatoires. Secret de groupe, jamais envoyé au serveur. |
| `K_enc` | `HKDF(ikm=K_g, salt="web3c-sync/v1", info="enc", L=32)` |
| `K_id` | `HKDF(ikm=K_g, salt="web3c-sync/v1", info="id", L=32)` |
| `K_name` | `HKDF(ikm=K_g, salt="web3c-sync/v1", info="name", L=32)` (noms d'appareils) |
| clé d'appareil | paire Ed25519, générée à l'appairage, stockée dans le coffre de l'OS. `devicePub` = 32 octets. |

## 3. Chiffrement d'un document

Entrées : `instance`, `groupId`, `collection`, `docId`, `plaintext` (octets).

1. **Bourrage** (Padmé simplifié, ISO 7816-4) : `m = plaintext || 0x80`, puis
   compléter avec `0x00` jusqu'à `L' = padme(len(plaintext) + 1)`.
   `padme(L)` : si `L < 2`, retourne `L`. Sinon `E = floor(log2(L))`,
   `S = floor(log2(E)) + 1`, `z = E - S`, `mask = (1 << z) - 1`,
   retourne `(L + mask) & ~mask`.
   Au déchiffrement : retirer les `0x00` de fin puis exiger un `0x80`.
2. **AAD** = `"web3c-sync/v1" || 0x00 || field(instance) || field(groupId) ||
   field(collection) || field(docId)`.
3. `nonce` = 12 octets aléatoires. `ct||tag = AES-256-GCM(K_enc, nonce, m, AAD)`.
4. **Enveloppe** = `0x01 || nonce || ct || tag` (octet de version `0x01`).

Déchiffrement : refuser toute enveloppe dont l'octet de version ≠ `0x01`, de
longueur < 1 + 12 + 16 + 1, ou dont l'authentification échoue. Les erreurs ne
révèlent pas la cause.

Le contenu en clair (`plaintext`) d'un document de synchro est un JSON :
`{"v":1,"u":<updatedAt epoch ms>,"d":<charge utile>}` ; une suppression logique
est portée par le serveur (§6.3), pas par le contenu.

## 4. Identifiant de document pseudonymisé

`docId = base64url( HMAC-SHA256(K_id, field(collection) || field(logicalId)) )`
(32 octets, 43 caractères). `collection` reste en clair dans l'URL (nom
générique : `progress`, `ratings`, `profiles`, …) ; le serveur applique la
liste de collections autorisées de son instance.

## 5. Authentification des requêtes

Chaque requête (sauf `GET /v1/health` et les routes publiques §9) porte :

| En-tête | Valeur |
|---|---|
| `X-Device` | `devicePub` en base64url |
| `X-Timestamp` | secondes Unix (entier décimal) |
| `X-Nonce` | 16 octets aléatoires, base64url |
| `X-Signature` | Ed25519 en base64url, sur la chaîne canonique ci-dessous |

Chaîne canonique (octets UTF-8, `\n` = 0x0A) :

```
web3c-sync/v1\n
<METHOD>\n
<path?query exactement comme envoyé>\n
<X-Timestamp>\n
<X-Nonce>\n
<hex minuscule de SHA-256(corps)>\n
<instance>
```

Le serveur refuse (401) si : signature invalide, |now − timestamp| > 120 s, nonce
déjà vu dans la fenêtre, ou (hors `join` et création) `devicePub` non membre du
groupe de l'URL. Le corps vide hache `e3b0c442…b855`.

## 6. Groupes et appareils

### 6.1 Création

`POST /v1/g` — corps JSON `{"groupId":"…"}`. Signée par la future clé du
propriétaire. 201. Si l'instance l'exige (serveur personnel), l'en-tête
`Authorization: Bearer <adminToken>` est obligatoire.
Le propriétaire est membre d'office.

### 6.2 Appairage

- Propriétaire : `POST /v1/g/{gid}/join-tokens` → `{"token":"<16 octets b64url>",
  "expiresAt":<epoch s>}`. Jeton à usage unique, valable **10 minutes** (le
  serveur ne stocke que `SHA-256(token)`).
- Nouvel appareil : `POST /v1/g/{gid}/join`, corps
  `{"token":"…","nameEnc":"<b64url enveloppe §3 de collection "_name">"}`, signée
  par la nouvelle clé (preuve de possession). 200 : l'appareil devient membre.
  Jeton déjà utilisé, expiré ou inconnu : 403 identique (pas d'oracle).
- QR / code d'appairage : `web3c-link:v1?s=<urlServeur>&i=<instance>&g=<groupId>&t=<token>&k=<K_g>[&f=<empreinteTLS>]`.

### 6.3 Membres

- `GET /v1/g/{gid}/members` → `[{"device":"…","nameEnc":"…","owner":bool,"joinedAt":s}]`.
- `DELETE /v1/g/{gid}/members/{device}` : propriétaire (révocation) ou l'appareil
  lui-même (départ). Le propriétaire ne peut pas être révoqué.
- Rotation de clé : voir §8.

### 6.4 Informations et effacement

- `GET /v1/g/{gid}/info` → `{"instance":"…","seq":n,"docs":n,"bytes":n,
  "quota":{…},"purgeAt":<epoch s>}` (date de purge pour inactivité).
- `DELETE /v1/g/{gid}` : propriétaire ; supprime tout (documents, blobs,
  membres, jetons). 204.

## 7. Documents

Chaque écriture dans un groupe incrémente un compteur `seq` du groupe.

- `PUT /v1/g/{gid}/d/{collection}/{docId}` — corps = enveloppe §3
  (`application/octet-stream`). **`If-Match: <seq>` obligatoire** : `0` pour une
  création, sinon le `seq` du document sur lequel le client s'est basé. 200 →
  `{"seq":n}`. 409 si le `seq` courant du document diffère ; la réponse porte
  `{"seq":n}` ; le client récupère, **fusionne** (le `u` interne le plus récent
  gagne), puis réécrit.
- `GET …` → corps = enveloppe ; en-têtes `X-Seq`, `X-Updated-At`.
- `DELETE …` (`If-Match` obligatoire) → tombstone : le contenu est effacé, `deleted`
  est vrai, `seq` augmente. Les tombstones sont conservés pour la vie du groupe.
- `GET /v1/g/{gid}/changes?since=N&limit=500` → `{"items":[{"collection":"…",
  "docId":"…","seq":n,"deleted":bool,"updatedAt":s,"env":"<b64url>"}],
  "next":N',"more":bool}`. `env` absent pour un tombstone. Ordre croissant de
  `seq`. Un client neuf utilise `since=0`.
- `GET /v1/g/{gid}/stream?since=N` — SSE : `id: <seq>`, événement `change`,
  données `{"collection":"…","docId":"…","seq":n,"deleted":bool}` (sans contenu :
  le client interroge `changes`). Signal de vie `: ping` toutes les 25 s.
  L'authentification est celle d'une requête GET ordinaire (§5).

Limites par instance (valeurs par défaut du serveur fourni) : document ≤ 256 KiB,
≤ 5 000 documents et ≤ 64 MiB par groupe, ≤ 120 écritures/minute/appareil.
Dépassement : 413 ou 429 avec un corps `{"error":"quota","limit":"…"}`.

## 8. Rotation de la clé de groupe (premier lot : manuelle)

La révocation d'un appareil ne retire pas la clé qu'il connaît. La rotation
manuelle : un membre génère `K_g'`, écrit le jeu de documents rechiffrés (sous
une nouvelle **époque**), distribue `K_g'` aux appareils restants par un nouvel
appairage (QR) ; le détail d'époque (champ `e` dans l'enveloppe, `0x02`) est
**réservé** : v1 n'accepte que l'octet de version `0x01`. Jusqu'à son
implémentation, la procédure de révocation sûre est : créer un nouveau groupe,
ré-appairer les appareils de confiance, supprimer l'ancien.

## 9. Notes communautaires (instance `iptv` uniquement)

Données en clair, volontairement minimales, sans lien avec un groupe ni un
appareil.

- `contentKey` : chaîne `[a-z0-9:_.-]{1,128}` choisie par le client (identité
  du contenu commune aux utilisateurs, ex. `movie:tmdb:603`).
- **Vote** : `PUT /v1/public/ratings/{contentKey}` (sans signature d'appareil),
  corps `{"p":"<pseudonyme b64url 32 octets>","r":<note>,"n":<nonce PoW>}`.
  - `pseudonyme = HMAC-SHA256(K_user, field("rating") || field(profileId) ||
    field(contentKey))`, où `K_user` est `K_id` si le profil a un groupe, sinon
    une clé locale aléatoire de l'appareil. Un vote par pseudonyme et par
    contenu ; un nouveau vote remplace l'ancien.
  - `r` : nombre dans `[ratingMin, ratingMax]` de l'instance (par défaut `[0,10]`).
    `r = null` retire le vote.
  - **Preuve de travail** : `SHA-256(field(contentKey) || field(p) ||
    canonique(r) || u64(n))` doit avoir au moins `powBits` bits de poids fort à 0
    (16 par défaut). `canonique(r)` = `r` en texte décimal le plus court
    (`7`, `7.5`, `null`).
  - Limitation de débit par IP (mémoire seule, rien n'est écrit sur disque).
- **Lecture** : `GET /v1/public/ratings/{contentKey}` → `{"count":n,"sum":x,
  "avg":x}` ; `POST /v1/public/ratings/query` `{"keys":[…≤100]}` →
  `{"items":{"<key>":{"count":n,"sum":x,"avg":x}}}`.
- Aucun texte libre. Le serveur ne stocke que `(contentKey, pseudonyme, note,
  date)`.

## 10. Blobs (réservé aux médias chiffrés)

`PUT/GET/DELETE /v1/g/{gid}/b/{blobId}`, `Range` pris en charge en lecture,
taille maximale par instance. Le format des segments chiffrés est défini par le
plan « chiffrement de bout en bout des médias » ; le serveur stocke des octets
opaques.

## 11. Erreurs

JSON `{"error":"<code>"}` avec : `bad_request` 400, `unauthorized` 401,
`forbidden` 403, `not_found` 404, `conflict` 409, `too_large` 413, `quota` 429,
`rate_limited` 429, `unavailable` 503. Les 401/403 ne distinguent pas les causes
d'échec d'authentification.

## 12. Vie privée du serveur

- Aucune adresse IP n'est écrite par le serveur. L'adresse IP vue par le
  serveur sert à la limitation de débit en mémoire seulement. Les journaux du
  proxy conservent l'adresse IP **7 jours**.
- Aucun contenu, jeton ou clé dans les journaux.
- Groupes inactifs purgés après **365 jours** (date visible via `/info`).

## 13. Vecteurs de test

`spec/vectors/v1.json` est généré par le serveur de référence
(`server/cmd/genvectors`). Il contient, avec des entrées fixes (graines
Ed25519, nonce AES-GCM forcé en test) : dérivation HKDF, `docId`, `padme`,
enveloppe complète, chaîne canonique + signature, preuve de travail, pseudonyme.
Les clients Dart et Swift **doivent** reproduire chaque sortie octet pour octet
et déchiffrer les enveloppes du fichier.
