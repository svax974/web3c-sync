# Modèle de données IPTV synchronisé (instance `iptv`)

Livrable du lot 0 du plan `2026-10-05-sync-web3c-backends-design.md`. Inventaire
relevé le 2026-10-05 sur VxIPTV Flutter (`packages/vxiptv_storage`), VxIPTV tvOS
(`apps/vxiptv/tvos`) et le module IPTV d'AICompanion. Ce modèle s'applique de la
même façon aux trois : un seul format sur le fil.

## 1. Constats qui gouvernent le modèle

1. **Aujourd'hui seules trois données sont synchronisées** : positions de reprise,
   notes personnelles, note communautaire. Profils, favoris, listes, ordre des
   chaînes, réglages, sources et identifiants ne le sont pas, ni sur Flutter ni
   sur tvOS.
2. **Un seul document Firestore par profil** contient tout l'historique et toutes
   les notes (maps) : limite de 1 Mio, relecture complète à chaque pull. Le
   nouveau modèle utilise **un document par élément**.
3. **Aucune suppression ne se propage** (pas de tombstone) : une entrée supprimée
   réapparaît au pull suivant. Le nouveau modèle propage les suppressions par marqueurs chiffrés.
4. **Règle de fusion incohérente** : la progression garde « la position la plus
   avancée », les notes « le plus récent ». Nouveau modèle : **le plus récent
   gagne, partout** (`u` interne), pour qu'un re-visionnage plus court ou une
   remise à zéro se propagent. La progression ajoute un indicateur `done`.
5. **L'identifiant de profil n'est pas partagé** entre appareils (UUID local) : les
   données de deux appareils ne se rejoignent que par coïncidence. Le nouveau
   modèle synchronise **les profils eux-mêmes**.
6. **Les identifiants de sources sont propres à chaque appareil** (UUID local). Une
   clé stable dérivée du contenu de la source (`sourceKey`) sert de pont.
7. **Identifiants Xtream/M3U et PIN parental en clair** dans le stockage local
   (Hive non chiffré, JSON tvOS). Une fois synchronisés ils sont chiffrés de bout
   en bout ; leur stockage local reste hors périmètre du protocole (à traiter
   séparément : Keychain/Keystore).
8. Le pull n'a lieu qu'à la sélection de profil et à la jonction d'un groupe, sans
   temps réel ni périodicité. Le nouveau modèle utilise SSE + rattrapage.

## 2. Collections (noms autorisés sur l'instance `iptv`)

`profiles, progress, ratings, favorites, lists, order, sources, prefs`
(`_name` est réservé au nom d'appareil, chiffré avec `K_name`.)

Pour chaque document, `k` (identifiant logique, voir PROTOCOL §3) et `d` (charge
utile JSON), `u` = `updatedAt` en millisecondes Unix, **fixé à l'instant de la
modification locale** (jamais à l'instant de la synchro).

| Collection | `k` | Charge utile `d` | Source locale |
|---|---|---|---|
| `profiles` | `profileId` (UUID v4, **stable**, adopté à l'appairage) | `{name, avatar, sources:[sourceKey], active: sourceKey?}` | box `profiles` / `profiles.json` |
| `progress` | `{profileId}/{type}_{id}` | `{pos, dur, done, name?, icon?, src?: sourceKey, series?: seriesId}` (secondes) | `history_{pid}` / `history.json` |
| `ratings` | `{profileId}/{type}_{id}` | `{r}` (note 2,4,6,8,10) | `ratings_{pid}` / `ratings.json` |
| `favorites` | `{profileId}/{type}_{id}` | `{name?, icon?, src?: sourceKey}` | `favorites_{pid}` / `favorites.json` |
| `lists` | `{profileId}/{listId}` | `{name, icon, items:[{type,id,name,icon}] }` | `custom_lists_{pid}` / `lists.json` |
| `order` | `{profileId}` | `{map:{"{src}_{streamId}": n}}` | `channel_order_{pid}` / `channel_order.json` |
| `sources` | `sourceKey` | `{name, type (xtream\|m3u), server?, user?, pass?, m3u?, epg?, active}` (`xmltvUrl` et infos de compte restent locaux) | box `playlists` / `playlists.json` |
| `prefs` | `app` | voir §4 | `AppSettings` / `settings.json` |

`type` ∈ `channel|movie|series`. `id` est l'identifiant du contenu chez la source
(entier chez Flutter, chaîne chez tvOS : sérialisé en texte). Les épisodes sont
conservés sous `series_{episodeId}` comme aujourd'hui.

### Suppression
Une suppression est un **marqueur chiffré** `{"del":true}` écrit comme n'importe quel
document (PROTOCOL §3), pas un `DELETE` serveur : le serveur ne peut ainsi pas
supprimer ni ressusciter un élément à l'insu des appareils. À réception d'un marqueur,
l'élément local est supprimé **sauf** si son `u` local est plus récent que le `u` du
marqueur (résurrection volontaire) ; les deux sont en millisecondes. Les tombstones
créés par le serveur sont ignorés (et signalés). Un marqueur ne porte aucune donnée ;
son `k` permet de retrouver l'élément.

### Clés dérivées
- `sourceKey = base64url(SHA-256(kind + "|" + serveur + "|" + utilisateur)[0..12])`
  (12 octets → 16 caractères). Xtream : `kind = "xtream"`, serveur = serveur
  **normalisé**, utilisateur tel que saisi (casse conservée). M3U : `kind = "m3u"`,
  serveur = l'URL complète saisie (espaces extérieurs retirés), utilisateur vide.
- **Normalisation du serveur** : sans schéma, `http://` est supposé ; schéma et
  hôte en minuscules ; port par défaut retiré (`:80` en http, `:443` en https) ;
  ni requête ni fragment ; barres obliques finales du chemin retirées.
- Les cas de référence sont dans `spec/vectors/iptv-v1.json` (`normalizeServer`,
  `sourceKey`, `doneThreshold`) ; chaque moteur (Dart, Swift) les rejoue en test.
- Un identifiant local de source adopte `sourceKey` quand elle est créée par la
  synchro.
- La clé de contenu `{type}_{id}` n'est pas qualifiée par la source (état
  historique) ; `src` en charge utile lève l'ambiguïté quand elle est connue.

## 3. Règles de fusion (toutes : le plus récent `u` gagne)

| Cas | Règle |
|---|---|
| Même `k`, deux `u` différents | `u` le plus grand gagne ; égalité : comparaison lexicographique de la charge utile sérialisée (déterministe) |
| `progress` | LWW sur `u` ; `done` vrai si `pos/dur ≥ 0,9` (seuil unique, remplace 0,92 de l'agent et 0,97 de tvOS) |
| Liste personnalisée | document entier : LWW sur la liste (pas de fusion élément par élément au premier lot) |
| `profiles` | LWW ; la suppression d'un profil publie des marqueurs de suppression (`profiles`, puis chaque doc `{profileId}/…`) |
| `sources` | LWW ; la suppression locale publie un marqueur de suppression |

**Précisions normatives** (décidées à l'implémentation du premier moteur, Flutter ;
tout autre moteur les respecte) :
- **Départage d'égalité de `u`** : la charge utile sérialisée **canonique** la plus
  grande l'emporte (comparaison d'octets UTF-8 ; clés triées à tous les niveaux,
  sans espaces).
- **Le serveur fait foi sans modification locale en attente** : une copie locale qui
  n'a aucun changement non envoyé adopte la version du serveur sans comparer les
  `u` (évite les dérives d'horloge). La comparaison par `u` ne s'applique que s'il
  existe un changement local non envoyé, ou si l'élément existait localement avant
  d'avoir jamais été synchronisé (il compte alors pour `u = 0` quand il n'a pas
  d'horodatage fiable : profil, liste, source, ordre, réglages).
- **Marqueur de suppression** : son `u` (millisecondes, fixé par l'appareil) se compare
  au `u` local ; un changement local plus récent l'emporte (résurrection).
- `progress.series` est l'identifiant de série **en texte**. Identifiants de
  contenu : sérialisés en texte dans les clés ; un moteur ignore ceux qu'il ne sait
  pas représenter.
- **Source dont l'adresse est modifiée** : sa `sourceKey` change ; l'ancienne est
  supprimée (marqueur), la nouvelle écrite, et les profils sont renvoyés.
- **Sources non résolubles** par ce profil (par ex. `syncSources` désactivé) : leurs
  clés restent dans la sélection du profil et sont réécrites telles quelles.
- Premier appairage d'un appareil neuf : un profil local **vide et jamais
  synchronisé** est supprimé silencieusement (sans tombstone) si des profils
  distants existent.
- Réglages utilisateur du moteur : `syncSources`, `syncPrefs`,
  `communityRatingsEnabled` (défaut vrai ; faux = rien n'est envoyé **ni lu** pour
  les notes communautaires).

Écriture : toujours `If-Match` (concurrence optimiste, PROTOCOL §7) ; sur 409,
relire, fusionner par la règle ci-dessus, réécrire.

## 4. Réglages synchronisés (`prefs`)

Synchronisés (communs à tous les appareils d'un utilisateur) : langue audio et
sous-titres par défaut, lecture auto, saut automatique de l'intro, page de
démarrage, rafraîchissement automatique (activé, intervalle), plateformes SVOD
activées, contrôle parental (activé, PIN).

**Non synchronisés** (propres à l'appareil) : décodage matériel, taille du tampon,
colonnes de grille, thème, gain audio, taille/couleur des sous-titres, lecteur par
défaut, clé TMDB, jetons Twitch, identifiants du serveur de synchro, empreinte
TLS, pointeur de groupe.

Clés de la charge utile `prefs` : `audio_lang`, `sub_lang`, `auto_play`,
`skip_intro`, `start_page` (`home|liveTV|vod|series`), `refresh_enabled`,
`refresh_days`, `svod` (liste triée), `parental_on`, `parental_pin`.
Un champ absent n'écrase jamais la valeur locale (compatibilité ascendante) ; un
`parental_pin` explicitement `null` efface le PIN.

## 5. Quotas pour l'instance `iptv`

Un document par élément : un profil actif peut avoir ~500 entrées d'historique,
des centaines de favoris et de notes. Défauts de l'instance `iptv` : 20 000
documents et 64 Mio par groupe, 256 Kio par document, 120 écritures/min/appareil
(la progression d'un film en cours s'écrit une fois par minute).

## 6. Couverture selon le backend

| Donnée | Firebase (existant) | Web3C / serveur perso |
|---|---|---|
| Positions de reprise, notes perso | oui (format actuel, **non chiffré**) | oui |
| Profils, favoris, listes, ordre, sources, réglages | **non** | oui |
| Tombstones / suppressions | non | oui |
| Chiffrement de bout en bout | non | oui |
| Notes communautaires | `ratings` (hérité) | **toujours** `sync-iptv.web3c.cc`, pour tous |

Firebase conserve son périmètre actuel : l'étendre à la couverture complète
obligerait à écrire en clair, chez un tiers, des identifiants de sources.
L'interface le signale par `supportsFullSync`.
