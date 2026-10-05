# Installateur du « serveur personnel » web3c-sync

Script POSIX `install.sh` exécuté **sur le serveur de l'utilisateur** (en root),
normalement piloté par SSH depuis l'app (`clients/dart_installer`). Il pose la
**même image Docker** que les déploiements Ansible (plan §5.7), derrière Caddy.

## Prérequis

- Linux avec `sh`, `openssl`, `curl`, `awk`/`sed`/`grep`, et **Docker + plugin
  `docker compose` v2**. Si Docker manque, `--install-docker` (explicite, jamais
  implicite) l'installe sur Debian/Ubuntu via `apt-get` (`docker.io`,
  `docker-compose-v2`) ; ailleurs, installez-le vous-même.
- Root (ou `sudo`). Ports **80 et 443 libres** (vérifiés avant toute action).
  Une seule instance par hôte (chacune veut 80/443).
- Mode domaine : un nom DNS qui pointe vers ce serveur, ports 80/443 joignables
  depuis Internet.
- Une image **publiée** (voir « Publier l'image »).

## Usage

```sh
# domaine (Let's Encrypt)
sh install.sh --instance iptv --tls domain=sync.exemple.org --email moi@exemple.org \
   --image ghcr.io/svax974/web3c-sync@sha256:<digest>
# sans domaine : certificat auto-signé (SAN = IP/noms fournis)
sh install.sh --instance banking --tls selfsigned --host 203.0.113.7
sh install.sh --instance iptv --status
sh install.sh --instance iptv --upgrade --image ghcr.io/svax974/web3c-sync:1.1.0
sh install.sh --instance iptv --uninstall [--purge-data]
```

Les modèles `docker-compose.yml.tpl` et `Caddyfile.tpl` doivent se trouver à côté
du script (ou `--templates DIR`). Défauts : image `$W3C_DEFAULT_IMAGE` ou
`ghcr.io/svax974/web3c-sync:latest` ; Caddy `caddy:2.8-alpine`
(`--caddy-image`, idéalement avec un digest). Chaque option a un équivalent
`W3C_*` (instance, image, tls, host, email, dir, port).

## Contrat de sortie

stdout = **une seule ligne** `WEB3C_RESULT {json}` ; tout le reste est sur stderr.

```json
{"ok":true,"action":"install","url":"https://…","instance":"iptv","adminToken":"<64 hex ou null>",
 "tlsFingerprint":"<SHA-256 DER feuille, base64url, ou null>","imageDigest":"sha256:…","version":"…","message":"…"}
{"ok":false,"error":"PORTS_BUSY","message":"…"}
```

Codes d'erreur : `USAGE INVALID_INSTANCE INVALID_ARG NOT_ROOT TOOL_MISSING
DOCKER_MISSING DOCKER_DAEMON DOCKER_INSTALL_FAILED PORTS_BUSY DNS_UNRESOLVED
PULL_FAILED CERT_FAILED START_FAILED HEALTH_FAILED NOT_INSTALLED LOCKED
SUBNET_UNAVAILABLE TEMPLATE_MISSING PERM_FAILED TOKEN_FAILED`. `--status`
ajoute `running` et `healthy`.

## Ce que ça installe (`/opt/web3c-sync/<instance>`, rien ailleurs)

| Fichier | Rôle |
|---|---|
| `server.env` (0600) | configuration `SYNC_*`, dont **SYNC_ADMIN_TOKEN_SHA256** |
| `install.state` (0600) | paramètres (image, TLS, sous-réseau) pour relances/mises à jour |
| `docker-compose.yml`, `Caddyfile` | générés depuis les modèles |
| `certs/` (0700) | cert + clé auto-signés (mode `selfsigned`) |
| `data/` (0700, uid 65532) | base SQLite + blobs — **conservés** à la désinstallation |
| `caddy-data/`, `caddy-config/` | état de Caddy (certificats Let's Encrypt) |

Conteneurs `w3c-sync-<instance>-server` et `-caddy`, réseau compose privé
`172.29.2xx.0/24` (choisi libre ; mémorisé).

## Sécurité

- **Jeton admin** : 32 octets aléatoires (hex), généré ici ; seul son SHA-256 est
  écrit (`server.env`, 0600). Affiché **une fois** dans `WEB3C_RESULT` (champ
  `adminToken`) puis jamais récupérable : une relance renvoie `adminToken:null` et
  conserve le hash. Il n'est ni sur la ligne de commande d'un processus, ni dans
  stderr, ni dans un fichier. Perdu = désinstaller/réinstaller.
- **Serveur** : jamais publié sur l'hôte ; utilisateur 65532, `read_only`,
  `cap_drop: ALL`, `no-new-privileges`, volume seul inscriptible. Métriques
  (`:9100`) non publiées ; `/metrics` répond 404 via Caddy.
- **Confiance proxy** : `SYNC_TRUST_PROXY=true`, `SYNC_TRUSTED_PROXIES` = uniquement
  le sous-réseau compose privé (Caddy seul y est client), `X-Real-IP` **écrasé**
  par Caddy (`header_up X-Real-IP {remote_host}`).
- **Caddy** : seul à publier 80/443 ; aucun préfixe d'URL ; SSE non bufferisé
  (`flush_interval -1`) ; corps limité à 17 MiB ; HSTS ; **aucun journal d'accès**
  (journal d'exécution WARN seulement, rotation 5 Mo x 3). Mêmes garde-fous que
  le vhost nginx `_sync-vhost.inc`.
- **TLS auto-signé** : ECDSA P-256, 10 ans, SAN = `--host`. L'empreinte renvoyée
  est le SHA-256 du certificat feuille DER, en base64url sans padding (format
  accepté par `parseFingerprint` de `web3c_sync`). Changer `--host` régénère le
  certificat donc change l'empreinte : les appareils doivent la ré-épingler.
- **Image épinglée** : après `pull`, la référence est résolue en
  `dépôt@sha256:…` dans le compose ; `imageDigest` est renvoyé.
- Toutes les valeurs (instance, domaine, hôtes, image, dossier) sont validées
  contre des listes blanches avant d'être injectées dans les modèles.
- `--upgrade` : en cas d'échec de santé, l'ancien compose/état est restauré.
- Le script ne touche que `/opt/web3c-sync/<instance>` et ses conteneurs ; il
  n'ouvre aucun pare-feu (80 et 443 entrants à votre charge). Docker contourne
  ufw pour les ports publiés.

## Désinstallation

`--uninstall` : `docker compose down`, supprime config/certificats/compose, **garde**
`data/` et `caddy-data/`. `--purge-data` supprime tout le dossier. Docker et les
images téléchargées ne sont pas retirés.

## Publier l'image (action humaine)

Le dépôt n'a ni remote ni registre : `ghcr.io/svax974/web3c-sync` **n'existe pas
encore**. Il faut : créer le dépôt distant, construire et pousser
(`docker build -t ghcr.io/svax974/web3c-sync:<version> server/ && docker push …`),
rendre le paquet public (sinon l'hôte distant ne peut pas le tirer sans
`docker login`), relever le digest (`docker buildx imagetools inspect`), et
l'utiliser (`--image …@sha256:…`) dans l'app. Idéalement ajouter le label
`org.opencontainers.image.version` au Dockerfile (le script le lit pour `version`,
sinon il retombe sur le tag). Le rôle Ansible construit aujourd'hui l'image sur
l'hôte à partir du même Dockerfile.

## Tests

`sh test/test.sh` : exécute `install.sh` avec de faux `docker`, `curl`, `ss`,
`getent` (dossier `test/shims/`), `openssl` **réel**, dans un répertoire
temporaire (`W3C_ROOT`, seam de test : pas de root, pas de chown). `shellcheck`
est lancé s'il est installé.

**Non vérifié** : un vrai démon Docker (le compose accepté par `docker compose`,
démarrage réel des conteneurs, `read_only` compatible avec l'image), une vraie
émission Let's Encrypt, le comportement réel de Caddy (Caddyfile non validé par
`caddy validate`), `--install-docker`, les chemins root/chown, d'autres systèmes
que Linux, la détection de ports avec un vrai `ss`, le DNS réel, `shellcheck`
(absent de cette machine).
