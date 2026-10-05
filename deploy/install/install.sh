#!/bin/sh
# Installateur du « serveur personnel » web3c-sync. S'exécute SUR le serveur de
# l'utilisateur (Linux + Docker), en root. Voir README.md.
#
# Contrat de sortie :
#   - stdout : UNE seule ligne, `WEB3C_RESULT {json}` (succès ou échec) ;
#   - stderr : tout le reste (progression). Le jeton admin n'y figure JAMAIS ;
#   - code de sortie non nul en cas d'échec.
# Le jeton administrateur est généré ici, jamais écrit sur le disque (seul son
# SHA-256 l'est, dans server.env 0600) et n'apparaît qu'une fois, dans la ligne
# WEB3C_RESULT de la première installation.
set -eu

PROG=install.sh
umask 077

# ---------------------------------------------------------------- utilitaires
log() { printf '%s\n' "$*" >&2; }

jesc() { # échappement JSON minimal d'une chaîne
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\t\r' '   '
}

LOCKDIR=""
cleanup() {
  if [ -n "$LOCKDIR" ] && [ -d "$LOCKDIR" ]; then rmdir "$LOCKDIR" 2>/dev/null || true; fi
  if [ -n "${TMPCONF:-}" ] && [ -f "$TMPCONF" ]; then rm -f "$TMPCONF"; fi
}
trap cleanup EXIT

fail() { # fail CODE MESSAGE [exit]
  printf 'WEB3C_RESULT {"ok":false,"error":"%s","message":"%s"}\n' "$1" "$(jesc "$2")"
  log "ERREUR [$1] $2"
  exit "${3:-1}"
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------ valeurs par défaut
DEFAULT_IMAGE=${W3C_DEFAULT_IMAGE:-ghcr.io/svax974/web3c-sync:latest}
DEFAULT_CADDY_IMAGE=${W3C_CADDY_IMAGE:-caddy:2.8-alpine}
ACTION=install
INSTANCE=${W3C_INSTANCE:-}
IMAGE=${W3C_IMAGE:-}
CADDY_IMAGE=$DEFAULT_CADDY_IMAGE
TLS=${W3C_TLS:-}
HOSTS=${W3C_HOST:-}
EMAIL=${W3C_EMAIL:-}
DIR=${W3C_DIR:-}
PORT=${W3C_PORT:-8080}
INSTALL_DOCKER=0
PURGE=0
TEMPLATES=
# Prefixe racine : SEAM DE TEST uniquement (écrit sous $W3C_ROOT/opt/... au lieu
# de /opt/..., sans exiger root ni chown). Vide en production.
ROOT=${W3C_ROOT:-}
HEALTH_RETRIES=${W3C_HEALTH_RETRIES:-60}
HEALTH_DELAY=${W3C_HEALTH_DELAY:-2}

usage() {
  cat >&2 <<'EOF'
Usage : install.sh [ACTION] --instance iptv|banking|aiteam [options]

Actions (défaut : --install) :
  --install      installe (idempotent : relancer ne change rien)
  --status       état de l'installation (n'écrit rien)
  --upgrade      nouvelle image (--image), données conservées
  --uninstall    arrête et supprime ; données conservées sauf --purge-data

Options :
  --instance NOM        iptv | banking | aiteam
  --image REF           image complète (tag ou @sha256:...) ; défaut : $W3C_DEFAULT_IMAGE
                        ou ghcr.io/svax974/web3c-sync:latest
  --tls domain=NOM      Caddy + Let's Encrypt (ports 80 et 443 requis)
  --tls selfsigned      certificat auto-signé (10 ans) ; exige --host
  --host IP|NOM[,...]   SAN du certificat auto-signé (le premier sert d'URL)
  --email ADRESSE       contact Let's Encrypt (facultatif)
  --dir CHEMIN          défaut /opt/web3c-sync/<instance>
  --port N              port interne du serveur (défaut 8080, jamais publié)
  --caddy-image REF     défaut caddy:2.8-alpine
  --install-docker      autorise l'installation de Docker (Debian/Ubuntu, apt)
  --purge-data          avec --uninstall : supprime aussi les données
  --templates DIR       dossier des modèles (défaut : celui du script)
EOF
}

# ------------------------------------------------------------------ arguments
IMAGE_EXPLICIT=0
[ -n "$IMAGE" ] && IMAGE_EXPLICIT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --install) ACTION=install ;;
    --status) ACTION=status ;;
    --upgrade) ACTION=upgrade ;;
    --uninstall) ACTION=uninstall ;;
    --instance) [ $# -ge 2 ] || fail USAGE "--instance demande une valeur" 2; INSTANCE=$2; shift ;;
    --image) [ $# -ge 2 ] || fail USAGE "--image demande une valeur" 2; IMAGE=$2; IMAGE_EXPLICIT=1; shift ;;
    --tls) [ $# -ge 2 ] || fail USAGE "--tls demande une valeur" 2; TLS=$2; shift ;;
    --host) [ $# -ge 2 ] || fail USAGE "--host demande une valeur" 2; HOSTS=$2; shift ;;
    --email) [ $# -ge 2 ] || fail USAGE "--email demande une valeur" 2; EMAIL=$2; shift ;;
    --dir) [ $# -ge 2 ] || fail USAGE "--dir demande une valeur" 2; DIR=$2; shift ;;
    --port) [ $# -ge 2 ] || fail USAGE "--port demande une valeur" 2; PORT=$2; shift ;;
    --caddy-image) [ $# -ge 2 ] || fail USAGE "--caddy-image demande une valeur" 2; CADDY_IMAGE=$2; shift ;;
    --templates) [ $# -ge 2 ] || fail USAGE "--templates demande une valeur" 2; TEMPLATES=$2; shift ;;
    --install-docker) INSTALL_DOCKER=1 ;;
    --purge-data) PURGE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail USAGE "option inconnue : $(printf '%.40s' "$1")" 2 ;;
  esac
  shift
done

# ----------------------------------------------------------------- validation
case "$INSTANCE" in
  iptv|banking|aiteam) ;;
  '') fail INVALID_INSTANCE "instance requise (iptv, banking ou aiteam)" 2 ;;
  *) fail INVALID_INSTANCE "instance invalide : doit valoir iptv, banking ou aiteam" 2 ;;
esac

case "$PORT" in
  ''|*[!0-9]*) fail INVALID_ARG "port interne invalide" 2 ;;
esac
{ [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ]; } || fail INVALID_ARG "port interne hors de 1024-65535" 2

valid_ref() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/:@-]*$'; }
valid_ref "$CADDY_IMAGE" || fail INVALID_ARG "référence d'image Caddy invalide" 2
if [ -n "$IMAGE" ]; then valid_ref "$IMAGE" || fail INVALID_ARG "référence d'image invalide" 2; fi

is_ipv4() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
is_ipv6() { printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*$'; }
is_fqdn() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'; }

if [ -n "$EMAIL" ]; then
  printf '%s' "$EMAIL" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$' || fail INVALID_ARG "adresse e-mail invalide" 2
fi

[ -n "$DIR" ] || DIR=/opt/web3c-sync/$INSTANCE
case "$DIR" in
  /*) ;;
  *) fail INVALID_ARG "--dir doit être un chemin absolu" 2 ;;
esac
printf '%s' "$DIR" | grep -Eq '^/[A-Za-z0-9._/-]+$' || fail INVALID_ARG "--dir contient des caractères non autorisés" 2
case "$DIR" in
  *..*) fail INVALID_ARG "--dir ne doit pas contenir « .. »" 2 ;;
esac
D=$ROOT$DIR
PROJECT=w3c-sync-$INSTANCE
STATE=$D/install.state
ENVF=$D/server.env

# ----------------------------------------------------------- état précédent
state_get() { [ -f "$STATE" ] && sed -n "s/^$1=//p" "$STATE" | head -n 1 || true; }

TLS_MODE=; TLS_DOMAIN=
CADDY_EXPLICIT=0
[ "$CADDY_IMAGE" = "$DEFAULT_CADDY_IMAGE" ] || CADDY_EXPLICIT=1
if [ -f "$STATE" ]; then
  # Une relance sans option reprend la configuration installée.
  [ -n "$TLS" ] || TLS=$(state_get tls)
  [ -n "$HOSTS" ] || HOSTS=$(state_get hosts)
  [ -n "$EMAIL" ] || EMAIL=$(state_get email)
  if [ "$IMAGE_EXPLICIT" = 0 ]; then IMAGE=$(state_get image_requested); fi
  if [ "$CADDY_EXPLICIT" = 0 ]; then c=$(state_get caddy_image); [ -z "$c" ] || CADDY_IMAGE=$c; fi
  if [ -z "${W3C_PORT:-}" ]; then p=$(state_get port); [ -z "$p" ] || PORT=$p; fi
fi
[ -n "$IMAGE" ] || IMAGE=$DEFAULT_IMAGE

if [ "$ACTION" = upgrade ] || [ "$ACTION" = status ]; then
  [ -f "$STATE" ] || fail NOT_INSTALLED "aucune installation de l'instance $INSTANCE dans $DIR"
fi
if [ "$ACTION" = install ] || [ "$ACTION" = upgrade ] || [ "$ACTION" = status ]; then
  case "$TLS" in
    domain=*)
      TLS_MODE=domain; TLS_DOMAIN=${TLS#domain=}
      is_fqdn "$TLS_DOMAIN" || fail INVALID_ARG "nom de domaine invalide" 2
      case "$TLS_DOMAIN" in
        *.*) ;;
        *) fail INVALID_ARG "le nom de domaine doit être complet (ex. sync.exemple.org)" 2 ;;
      esac
      is_ipv4 "$TLS_DOMAIN" && fail INVALID_ARG "une adresse IP n'est pas un nom de domaine : utilisez --tls selfsigned" 2
      ;;
    selfsigned)
      TLS_MODE=selfsigned
      [ -n "$HOSTS" ] || fail INVALID_ARG "--tls selfsigned exige --host <IP ou nom>[,...]" 2
      oldifs=$IFS; IFS=,
      for h in $HOSTS; do
        if is_ipv4 "$h" || is_ipv6 "$h" || is_fqdn "$h"; then :; else
          IFS=$oldifs; fail INVALID_ARG "valeur --host invalide" 2
        fi
      done
      IFS=$oldifs
      ;;
    '') fail INVALID_ARG "mode TLS requis : --tls domain=<nom> ou --tls selfsigned --host <IP>" 2 ;;
    *) fail INVALID_ARG "mode TLS inconnu (domain=<nom> | selfsigned)" 2 ;;
  esac
fi

if [ "$ACTION" = install ] || [ "$ACTION" = upgrade ] || [ "$ACTION" = uninstall ]; then
  if [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
    fail NOT_ROOT "doit s'exécuter en root (sudo)"
  fi
fi

if [ -z "$TEMPLATES" ]; then
  TEMPLATES=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fi

# ------------------------------------------------------------------ pré-requis
need_cmd openssl || fail TOOL_MISSING "openssl est requis"
need_cmd sed || fail TOOL_MISSING "sed est requis"
need_cmd curl || fail TOOL_MISSING "curl est requis"

docker_ready() { need_cmd docker; }

install_docker() {
  if [ "$INSTALL_DOCKER" != 1 ]; then
    fail DOCKER_MISSING "Docker (avec le plugin « docker compose » v2) est absent. Installez-le, ou relancez avec --install-docker (Debian/Ubuntu)."
  fi
  [ -z "$ROOT" ] || fail DOCKER_MISSING "installation de Docker désactivée en mode test"
  if [ -r /etc/os-release ] && grep -Eqi '^ID(_LIKE)?=.*(debian|ubuntu)' /etc/os-release && need_cmd apt-get; then
    log "Installation de Docker depuis les paquets de la distribution (apt-get : docker.io, docker-compose-v2)..."
    DEBIAN_FRONTEND=noninteractive apt-get update >&2 || fail DOCKER_INSTALL_FAILED "apt-get update a échoué"
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 >&2 \
      || fail DOCKER_INSTALL_FAILED "apt-get install docker.io docker-compose-v2 a échoué (le plugin compose v2 n'existe pas sur toutes les versions : installez Docker selon docs.docker.com)"
    if need_cmd systemctl; then systemctl enable --now docker >&2 || true; fi
  else
    fail DOCKER_MISSING "installation automatique de Docker prise en charge seulement sur Debian/Ubuntu ; installez Docker selon docs.docker.com"
  fi
}

check_docker() {
  if ! docker_ready; then install_docker; fi
  docker_ready || fail DOCKER_MISSING "Docker introuvable après installation"
  docker compose version >/dev/null 2>&1 \
    || { if [ "$INSTALL_DOCKER" = 1 ] && [ -z "$ROOT" ]; then install_docker; fi
         docker compose version >/dev/null 2>&1 \
           || fail DOCKER_MISSING "le plugin « docker compose » (v2) est absent"; }
  docker info >/dev/null 2>&1 || fail DOCKER_DAEMON "le démon Docker ne répond pas (docker info)"
}

# ----------------------------------------------------------------- vérifications
port_busy() {
  if need_cmd ss; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
  elif need_cmd netstat; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
  else
    log "AVERTISSEMENT : ni ss ni netstat, conflits de ports non vérifiés."
    return 1
  fi
}

our_caddy_running() {
  [ -n "$(docker ps -q --filter "name=^${PROJECT}-caddy\$" 2>/dev/null)" ]
}

check_ports() {
  our_caddy_running && return 0
  for p in 80 443; do
    if port_busy "$p"; then
      fail PORTS_BUSY "le port $p est déjà utilisé sur ce serveur ; Caddy a besoin de 80 et 443 (rien n'a été modifié)"
    fi
  done
}

check_dns() {
  [ "$TLS_MODE" = domain ] || return 0
  ips=""
  if need_cmd getent; then
    ips=$(getent ahosts "$TLS_DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u || true)
  elif need_cmd dig; then
    ips=$(dig +short "$TLS_DOMAIN" 2>/dev/null || true)
  fi
  if [ -z "$ips" ]; then
    if need_cmd getent || need_cmd dig; then
      fail DNS_UNRESOLVED "le nom $TLS_DOMAIN ne se résout pas : créez l'enregistrement DNS vers ce serveur avant d'installer (Let's Encrypt échouerait)"
    fi
    log "AVERTISSEMENT : ni getent ni dig, DNS non vérifié."
    return 0
  fi
  mine=""
  if need_cmd ip; then mine=$(ip -o addr 2>/dev/null | awk '{print $4}' | sed 's#/.*##' || true); fi
  if [ -n "$mine" ]; then
    found=0
    for a in $ips; do
      for m in $mine; do [ "$a" = "$m" ] && found=1; done
    done
    if [ "$found" = 0 ]; then
      log "AVERTISSEMENT : $TLS_DOMAIN ne pointe vers aucune adresse locale de ce serveur (NAT/IP publique différente ?)."
      log "  Let's Encrypt échouera si le nom ne mène pas à ce serveur."
    fi
  fi
}

# ----------------------------------------------------------------- sous-réseau
used_subnets() {
  ids=$(docker network ls -q 2>/dev/null || true)
  # shellcheck disable=SC2086
  [ -z "$ids" ] || docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $ids 2>/dev/null || true
  if need_cmd ip; then ip -4 -o route 2>/dev/null | awk '{print $1}' || true; fi
}

pick_subnet() {
  s=$(state_get subnet)
  if [ -n "$s" ]; then SUBNET=$s; return; fi
  used=$(used_subnets)
  case "$INSTANCE" in iptv) n=0 ;; banking) n=1 ;; *) n=2 ;; esac
  i=0
  while [ "$i" -lt 50 ]; do
    cand=172.29.$((200 + (n + i) % 50)).0/24
    if ! printf '%s\n' "$used" | tr ' ' '\n' | grep -Fxq "$cand"; then SUBNET=$cand; return; fi
    i=$((i + 1))
  done
  fail SUBNET_UNAVAILABLE "aucun sous-réseau 172.29.200-249.0/24 libre pour le réseau privé"
}

# ------------------------------------------------------------------------ image
resolve_image() { # pull puis fixe IMAGE_PINNED, IMAGE_DIGEST, VERSION
  log "Téléchargement de l'image $IMAGE ..."
  docker pull "$IMAGE" >&2 || fail PULL_FAILED "impossible de télécharger l'image $IMAGE (publiée ? réseau ? registre privé ?)"
  rd=$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)
  case "$rd" in
    *@sha256:*) IMAGE_DIGEST=${rd##*@}; repo=${rd%@*}; IMAGE_PINNED=$repo@$IMAGE_DIGEST ;;
    *)
      IMAGE_DIGEST=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
      [ -n "$IMAGE_DIGEST" ] || fail PULL_FAILED "l'image $IMAGE est introuvable après téléchargement"
      IMAGE_PINNED=$IMAGE
      log "AVERTISSEMENT : pas de digest de dépôt pour cette image (image locale ?) ; épinglée par identifiant seulement."
      ;;
  esac
  VERSION=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE" 2>/dev/null || true)
  case "$VERSION" in ''|'<no value>') VERSION=
    case "$IMAGE" in
      *@sha256:*) VERSION=unknown ;;
      *:*) t=${IMAGE##*:}; case "$t" in */*) VERSION=unknown ;; *) VERSION=$t ;; esac ;;
      *) VERSION=unknown ;;
    esac ;;
  esac
  printf '%s' "$IMAGE_PINNED" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._/:@-]*$' || fail PULL_FAILED "référence d'image épinglée invalide"
}

# --------------------------------------------------------------------- fichiers
render() { # render SRC DST  (les valeurs ont été validées : pas de métacaractère sed)
  sed -e "s|@@INSTANCE@@|$INSTANCE|g" \
      -e "s|@@PROJECT@@|$PROJECT|g" \
      -e "s|@@IMAGE@@|$IMAGE_PINNED|g" \
      -e "s|@@CADDY_IMAGE@@|$CADDY_IMAGE|g" \
      -e "s|@@SUBNET@@|$SUBNET|g" \
      -e "s|@@PORT@@|$PORT|g" \
      -e "s|@@SITE@@|$SITE_ADDR|g" \
      -e "s|@@TLS_LINE@@|$TLS_LINE|g" \
      -e "s|@@EMAIL_LINE@@|$EMAIL_LINE|g" \
      "$1" > "$2"
}

gen_cert() {
  CERT=$D/certs/cert.pem; KEY=$D/certs/key.pem
  want=$(printf '%s' "$HOSTS")
  if [ -f "$CERT" ] && [ -f "$KEY" ] && [ "$(state_get cert_hosts)" = "$want" ]; then
    log "Certificat auto-signé existant conservé."
    return
  fi
  log "Génération du certificat auto-signé (ECDSA P-256, 10 ans)..."
  TMPCONF=$D/certs/openssl.cnf.tmp
  first=${HOSTS%%,*}
  {
    printf '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
    printf '[dn]\nCN=%s\n' "$first"
    printf '[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=@san\n'
    printf '[san]\n'
    i=1; oldifs=$IFS; IFS=,
    for h in $HOSTS; do
      if is_ipv4 "$h" || is_ipv6 "$h"; then printf 'IP.%s=%s\n' "$i" "$h"; else printf 'DNS.%s=%s\n' "$i" "$h"; fi
      i=$((i + 1))
    done
    IFS=$oldifs
  } > "$TMPCONF"
  openssl ecparam -name prime256v1 -genkey -noout -out "$KEY" 2>/dev/null \
    && openssl req -x509 -new -key "$KEY" -days 3650 -sha256 -config "$TMPCONF" -out "$CERT" 2>/dev/null \
    || fail CERT_FAILED "génération du certificat auto-signé impossible (openssl)"
  rm -f "$TMPCONF"; TMPCONF=
  chmod 600 "$KEY"; chmod 644 "$CERT"
}

cert_fingerprint() { # SHA-256 du certificat FEUILLE (DER), base64url sans padding
  openssl x509 -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# ------------------------------------------------------------------------ santé
site_url() {
  if [ "$TLS_MODE" = domain ]; then printf 'https://%s' "$TLS_DOMAIN"; else
    f=${HOSTS%%,*}; if is_ipv6 "$f"; then printf 'https://[%s]' "$f"; else printf 'https://%s' "$f"; fi
  fi
}

health_once() {
  url=$(site_url)
  if [ "$TLS_MODE" = domain ]; then
    out=$(curl -fsS --max-time 8 --connect-to "::127.0.0.1:443" "$url/v1/health" 2>/dev/null) || return 1
  else
    out=$(curl -fsSk --max-time 8 --connect-to "::127.0.0.1:443" "$url/v1/health" 2>/dev/null) || return 1
  fi
  printf '%s' "$out" | grep -Eq '"ok" *: *true'
}

wait_health() {
  n=0
  while [ "$n" -lt "$HEALTH_RETRIES" ]; do
    if health_once; then return 0; fi
    n=$((n + 1))
    [ "$HEALTH_DELAY" -le 0 ] || sleep "$HEALTH_DELAY"
  done
  return 1
}

health_diag() {
  log "--- journaux récents (serveur) ---"
  docker logs --tail 20 "${PROJECT}-server" >&2 2>&1 || true
  log "--- journaux récents (caddy) ---"
  docker logs --tail 20 "${PROJECT}-caddy" >&2 2>&1 || true
}

compose() { docker compose -f "$D/docker-compose.yml" -p "$PROJECT" "$@" >&2; }

emit() { # emit ACTION TOKEN|"" FINGERPRINT|"" MESSAGE
  tok=null; [ -z "$2" ] || tok="\"$2\""
  fp=null; [ -z "$3" ] || fp="\"$3\""
  printf 'WEB3C_RESULT {"ok":true,"action":"%s","url":"%s","instance":"%s","adminToken":%s,"tlsFingerprint":%s,"imageDigest":"%s","version":"%s","message":"%s"}\n' \
    "$1" "$(site_url)" "$INSTANCE" "$tok" "$fp" "$(jesc "$IMAGE_DIGEST")" "$(jesc "$VERSION")" "$(jesc "$4")"
}

write_state() {
  {
    printf 'instance=%s\n' "$INSTANCE"
    printf 'image_requested=%s\n' "$IMAGE"
    printf 'caddy_image=%s\n' "$CADDY_IMAGE"
    printf 'image_pinned=%s\n' "$IMAGE_PINNED"
    printf 'image_digest=%s\n' "$IMAGE_DIGEST"
    printf 'version=%s\n' "$VERSION"
    printf 'tls=%s\n' "$TLS"
    printf 'hosts=%s\n' "$HOSTS"
    printf 'cert_hosts=%s\n' "$HOSTS"
    printf 'email=%s\n' "$EMAIL"
    printf 'subnet=%s\n' "$SUBNET"
    printf 'port=%s\n' "$PORT"
  } > "$STATE.new"
  chmod 600 "$STATE.new"; mv -f "$STATE.new" "$STATE"
}

prepare_tls_vars() {
  if [ "$TLS_MODE" = domain ]; then
    SITE_ADDR=$TLS_DOMAIN; TLS_LINE='# TLS : Let'"'"'s Encrypt automatique (Caddy)'
  else
    f=${HOSTS%%,*}
    if is_ipv6 "$f"; then SITE_ADDR="https://[$f]"; else SITE_ADDR="https://$f"; fi
    TLS_LINE='tls /certs/cert.pem /certs/key.pem'
  fi
  if [ -n "$EMAIL" ]; then EMAIL_LINE="email $EMAIL"; else EMAIL_LINE='# (pas de contact Let'"'"'s Encrypt)'; fi
}

take_lock() {
  mkdir -p "$D"; chmod 700 "$D"
  if mkdir "$D/.lock" 2>/dev/null; then LOCKDIR=$D/.lock; else
    fail LOCKED "une autre opération est en cours dans $DIR (supprimez $DIR/.lock si elle est morte)"
  fi
}

check_templates() {
  for t in docker-compose.yml.tpl Caddyfile.tpl; do
    [ -f "$TEMPLATES/$t" ] || fail TEMPLATE_MISSING "modèle $t introuvable dans $TEMPLATES"
  done
}

# ------------------------------------------------------------------ actions
do_install() {
  check_templates
  check_docker
  check_ports
  check_dns
  [ ! -f "$STATE" ] || [ "$(state_get instance)" = "$INSTANCE" ] || fail INVALID_INSTANCE "$DIR appartient à une autre instance"
  take_lock
  mkdir -p "$D/data" "$D/caddy-data" "$D/caddy-config" "$D/certs"
  chmod 700 "$D/data" "$D/caddy-data" "$D/caddy-config" "$D/certs"
  if [ -z "$ROOT" ]; then chown 65532:65532 "$D/data" || fail PERM_FAILED "chown du volume de données impossible"; fi

  # Jeton : généré seulement à la première installation.
  TOKEN=""
  existing=""
  [ ! -f "$ENVF" ] || existing=$(sed -n 's/^SYNC_ADMIN_TOKEN_SHA256=//p' "$ENVF" | head -n 1)
  if printf '%s' "$existing" | grep -Eq '^[0-9a-f]{64}$'; then
    HASH=$existing
    MSG="installation déjà en place : le jeton administrateur existant est conservé et n'est plus affichable (seul son empreinte est stockée). Pour en obtenir un nouveau : désinstaller puis réinstaller."
  else
    TOKEN=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    [ "${#TOKEN}" = 64 ] || fail TOKEN_FAILED "génération du jeton impossible"
    HASH=$(printf '%s' "$TOKEN" | openssl dgst -sha256 | sed 's/^.*= *//')
    MSG="installé"
  fi

  FP=""
  if [ "$TLS_MODE" = selfsigned ]; then
    gen_cert
    FP=$(cert_fingerprint "$D/certs/cert.pem")
    [ -n "$FP" ] || fail CERT_FAILED "empreinte du certificat introuvable"
  fi

  pick_subnet
  resolve_image
  prepare_tls_vars

  {
    printf 'SYNC_INSTANCE=%s\n' "$INSTANCE"
    printf 'SYNC_LISTEN=:%s\n' "$PORT"
    printf 'SYNC_METRICS_LISTEN=:9100\n'
    printf 'SYNC_DB=/data/sync.db\n'
    printf 'SYNC_BLOB_DIR=/data/blobs\n'
    printf 'SYNC_COLLECTIONS=*\n'
    printf 'SYNC_TRUST_PROXY=true\n'
    printf 'SYNC_TRUSTED_PROXIES=%s\n' "$SUBNET"
    printf 'SYNC_REAL_IP_HEADER=X-Real-IP\n'
    printf 'SYNC_ADMIN_TOKEN_SHA256=%s\n' "$HASH"
  } > "$ENVF.new"
  chmod 600 "$ENVF.new"; mv -f "$ENVF.new" "$ENVF"

  [ -f "$D/docker-compose.yml" ] && cp -f "$D/docker-compose.yml" "$D/docker-compose.yml.prev" || true
  render "$TEMPLATES/docker-compose.yml.tpl" "$D/docker-compose.yml"
  render "$TEMPLATES/Caddyfile.tpl" "$D/Caddyfile"
  write_state

  log "Démarrage des conteneurs..."
  compose up -d || fail START_FAILED "docker compose up a échoué"
  log "Attente de /v1/health via Caddy (Let's Encrypt peut prendre quelques dizaines de secondes)..."
  if ! wait_health; then
    health_diag
    fail HEALTH_FAILED "le serveur ne répond pas à /v1/health via Caddy (voir stderr ; avec un domaine : DNS, ports 80/443 joignables depuis Internet ?)"
  fi
  emit install "$TOKEN" "$FP" "$MSG"
}

require_installed() {
  [ -f "$STATE" ] && [ -f "$D/docker-compose.yml" ] || fail NOT_INSTALLED "aucune installation de l'instance $INSTANCE dans $DIR"
}

load_installed() {
  IMAGE_PINNED=$(state_get image_pinned); IMAGE_DIGEST=$(state_get image_digest); VERSION=$(state_get version)
  SUBNET=$(state_get subnet); PORT=$(state_get port)
}

do_status() {
  require_installed
  load_installed
  running=false
  if need_cmd docker && [ -n "$(docker ps -q --filter "name=^${PROJECT}-server\$" 2>/dev/null)" ]; then running=true; fi
  healthy=false
  if [ "$running" = true ] && health_once; then healthy=true; fi
  FP=""; [ "$TLS_MODE" != selfsigned ] || FP=$(cert_fingerprint "$D/certs/cert.pem")
  tok=null; fp=null; [ -z "$FP" ] || fp="\"$FP\""
  printf 'WEB3C_RESULT {"ok":true,"action":"status","url":"%s","instance":"%s","adminToken":%s,"tlsFingerprint":%s,"imageDigest":"%s","version":"%s","running":%s,"healthy":%s,"message":"%s"}\n' \
    "$(site_url)" "$INSTANCE" "$tok" "$fp" "$(jesc "$IMAGE_DIGEST")" "$(jesc "$VERSION")" "$running" "$healthy" "état"
  [ "$healthy" = true ] || log "Le serveur ne répond pas correctement."
}

do_upgrade() {
  require_installed
  check_templates
  check_docker
  take_lock
  load_installed
  [ "$IMAGE_EXPLICIT" = 1 ] || log "Pas de --image : ré-installation de $IMAGE (tag à jour ?)."
  OLD_COMPOSE=$D/docker-compose.yml.prev; cp -f "$D/docker-compose.yml" "$OLD_COMPOSE"
  OLD_STATE=$STATE.prev; cp -f "$STATE" "$OLD_STATE"
  resolve_image
  prepare_tls_vars
  # La même version de Caddy que l'installation courante, sauf --caddy-image.
  render "$TEMPLATES/docker-compose.yml.tpl" "$D/docker-compose.yml"
  render "$TEMPLATES/Caddyfile.tpl" "$D/Caddyfile"
  write_state
  compose up -d || { restore_prev; fail START_FAILED "docker compose up a échoué (ancienne version restaurée)"; }
  if ! wait_health; then
    health_diag
    restore_prev
    fail HEALTH_FAILED "la nouvelle version ne répond pas ; ancienne version restaurée, données intactes"
  fi
  FP=""; [ "$TLS_MODE" != selfsigned ] || FP=$(cert_fingerprint "$D/certs/cert.pem")
  emit upgrade "" "$FP" "mis à jour, données conservées"
}

restore_prev() {
  log "Restauration de la version précédente..."
  cp -f "$OLD_COMPOSE" "$D/docker-compose.yml"; cp -f "$OLD_STATE" "$STATE"
  compose up -d || log "AVERTISSEMENT : la restauration a échoué."
}

do_uninstall() {
  [ -d "$D" ] || fail NOT_INSTALLED "aucune installation de l'instance $INSTANCE dans $DIR"
  check_docker
  take_lock
  if [ -f "$D/docker-compose.yml" ]; then compose down --remove-orphans || log "AVERTISSEMENT : compose down a échoué."; fi
  IMAGE_DIGEST=$(state_get image_digest); VERSION=$(state_get version)
  if [ "$PURGE" = 1 ]; then
    LOCKDIR=""   # le répertoire va disparaître
    rm -rf "$D"
    log "Données supprimées ($DIR)."
    msg="désinstallé, données supprimées"
  else
    rm -f "$D/docker-compose.yml" "$D/docker-compose.yml.prev" "$D/Caddyfile" "$ENVF" "$STATE" "$STATE.prev"
    rm -rf "$D/certs"
    msg="désinstallé ; données conservées dans $DIR/data (et $DIR/caddy-data). --purge-data pour les supprimer."
  fi
  printf 'WEB3C_RESULT {"ok":true,"action":"uninstall","url":null,"instance":"%s","adminToken":null,"tlsFingerprint":null,"imageDigest":null,"version":null,"message":"%s"}\n' \
    "$INSTANCE" "$(jesc "$msg")"
}

case "$ACTION" in
  install) do_install ;;
  status) do_status ;;
  upgrade) do_upgrade ;;
  uninstall) do_uninstall ;;
esac
