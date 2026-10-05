#!/bin/sh
# Tests de install.sh SANS Docker réel : faux docker/curl/ss/getent (shims/),
# openssl RÉEL, racine temporaire (W3C_ROOT). Usage : sh test.sh
# Non couvert : vrai Docker, vraie émission Let's Encrypt, vrai sshd/root, chown.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL=$(dirname "$HERE")/install.sh
PASS=0; FAILS=0
ok()  { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAILS=$((FAILS + 1)); printf '  FAIL %s\n' "$1"; }
check() { # check DESC CMD...
  d=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}

T=$(mktemp -d "${TMPDIR:-/tmp}/w3c-install-test.XXXXXX")
trap 'rm -rf "$T"' EXIT

mkbin() { # mkbin DIR [withdocker]
  mkdir -p "$1"
  for c in dash sh awk sed grep tr od head sort id dirname mkdir chmod mv cp rm rmdir cat sleep uname wc cut ls touch openssl; do
    p=$(command -v "$c" 2>/dev/null) && [ -x "$p" ] && ln -sf "$p" "$1/$c"
  done
  for s in curl ss getent; do cp "$HERE/shims/$s" "$1/$s"; done
  [ "${2:-}" = withdocker ] && cp "$HERE/shims/docker" "$1/docker"
  return 0
}

fresh() { # nouvel environnement isolé
  rm -rf "$T/e"; mkdir -p "$T/e/state" "$T/e/root"
  mkbin "$T/e/bin" withdocker
  mkbin "$T/e/bin-nodocker"
  E=$T/e; R=$E/root; S=$E/state
}

run() { # run [--nodocker] ARGS... -> $E/out, $E/err, $RC
  bp=$E/bin; if [ "$1" = --nodocker ]; then bp=$E/bin-nodocker; shift; fi
  env -i PATH="$bp" HOME="$E" W3C_ROOT="$R" SHIM_STATE="$S" W3C_HEALTH_RETRIES=2 W3C_HEALTH_DELAY=0 \
    sh "$INSTALL" "$@" > "$E/out" 2> "$E/err"
  RC=$?
}

pyj() { # pyj 'expr sur d' : évalue sur la dernière ligne WEB3C_RESULT
  python3 - "$E/out" "$1" <<'PY'
import json,sys
lines=open(sys.argv[1]).read().splitlines()
assert len(lines)==1 and lines[0].startswith("WEB3C_RESULT "), lines
d=json.loads(lines[0][len("WEB3C_RESULT "):])
sys.exit(0 if eval(sys.argv[2]) else 1)
PY
}
jget() { python3 -c 'import json,sys
l=open(sys.argv[1]).read().splitlines()[0][13:]
v=json.loads(l).get(sys.argv[2]); print("" if v is None else v)' "$E/out" "$1"; }

INST=iptv
D() { echo "$R/opt/web3c-sync/${1:-$INST}"; }
sha256hex() { python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }
mode() { python3 -c 'import os,sys;print(oct(os.stat(sys.argv[1]).st_mode & 0o777)[2:])' "$1"; }

echo "== installation auto-signée"
fresh
run --instance iptv --tls selfsigned --host 203.0.113.7,sync.example.net
check "code de sortie 0" test "$RC" = 0
check "stdout = exactement une ligne WEB3C_RESULT valide, ok" pyj 'd["ok"] is True'
TOKEN=$(jget adminToken)
check "jeton = 64 hex" sh -c "printf '%s' '$TOKEN' | grep -Eq '^[0-9a-f]{64}\$'"
check "url / instance / digest / version" pyj 'd["url"]=="https://203.0.113.7" and d["instance"]=="iptv" and d["imageDigest"].startswith("sha256:a") and d["version"]=="1.2.3"'
check "jeton absent de stderr" sh -c "! grep -q '$TOKEN' '$E/err'"
check "jeton absent de tous les fichiers écrits" sh -c "! grep -rq '$TOKEN' '$R'"
check "jeton absent des appels docker/curl" sh -c "! grep -q '$TOKEN' '$S'/*.log"
HASH=$(sed -n 's/^SYNC_ADMIN_TOKEN_SHA256=//p' "$(D)/server.env")
check "server.env contient SHA-256(jeton)" test "$HASH" = "$(sha256hex "$TOKEN")"
check "server.env 0600" test "$(mode "$(D)/server.env")" = 600
check "install.state 0600" test "$(mode "$(D)/install.state")" = 600
check "key.pem 0600" test "$(mode "$(D)/certs/key.pem")" = 600
check "data 0700" test "$(mode "$(D)/data")" = 700
FP=$(jget tlsFingerprint)
REAL=$(openssl x509 -in "$(D)/certs/cert.pem" -outform DER | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
check "empreinte du certificat feuille = recalcul openssl" test "$FP" = "$REAL"
check "empreinte au format base64url 43 car." sh -c "printf '%s' '$FP' | grep -Eq '^[A-Za-z0-9_-]{43}\$'"
check "certificat : validité ~10 ans" sh -c "openssl x509 -in '$(D)/certs/cert.pem' -noout -checkend $((3600*24*3600)) && ! openssl x509 -in '$(D)/certs/cert.pem' -noout -checkend $((3700*24*3600))"
SAN=$(openssl x509 -in "$(D)/certs/cert.pem" -noout -ext subjectAltName 2>/dev/null || openssl x509 -in "$(D)/certs/cert.pem" -noout -text)
check "SAN IP et DNS" sh -c "printf '%s' '$SAN' | grep -q '203.0.113.7' && printf '%s' '$SAN' | grep -q 'sync.example.net'"
check "env : SYNC_* attendus" sh -c "grep -qx 'SYNC_TRUST_PROXY=true' '$(D)/server.env' && grep -qx 'SYNC_REAL_IP_HEADER=X-Real-IP' '$(D)/server.env' && grep -qx 'SYNC_COLLECTIONS=\*' '$(D)/server.env' && grep -qx 'SYNC_INSTANCE=iptv' '$(D)/server.env' && grep -qx 'SYNC_LISTEN=:8080' '$(D)/server.env'"
SUBNET=$(sed -n 's/^SYNC_TRUSTED_PROXIES=//p' "$(D)/server.env")
check "SYNC_TRUSTED_PROXIES = un seul /24 privé" sh -c "printf '%s' '$SUBNET' | grep -Eq '^172\.29\.[0-9]+\.0/24\$'"
check "compose : même sous-réseau que la confiance" grep -q "subnet: $SUBNET" "$(D)/docker-compose.yml"
check "compose : image épinglée par digest" grep -q 'image: ghcr.io/svax974/web3c-sync@sha256:a' "$(D)/docker-compose.yml"
check "compose : aucun placeholder restant" sh -c "! grep -q '@@' '$(D)/docker-compose.yml' '$(D)/Caddyfile'"
python3 - "$(D)/docker-compose.yml" <<'PY' && ok "compose : seul caddy publie 80/443, serveur sans ports" || bad "compose : seul caddy publie 80/443, serveur sans ports"
import re,sys
t=open(sys.argv[1]).read()
srv=t.split("  caddy:")[0]
cad=t.split("  caddy:")[1].split("networks:\n  internal")[0]
assert not re.search(r"^\s+ports:",srv,re.M), "serveur publie des ports"
assert "read_only: true" in srv and "cap_drop: [ALL]" in srv and "no-new-privileges" in srv and '65532:65532' in srv
ports=re.findall(r'-\s+"(\d+:\d+)"',cad)
assert ports==["80:80","443:443"], ports
PY
check "Caddyfile : X-Real-IP écrasé" grep -q 'header_up X-Real-IP {remote_host}' "$(D)/Caddyfile"
check "Caddyfile : flush SSE, 17MiB, /metrics 404, HSTS, tls cert" sh -c "grep -q 'flush_interval -1' '$(D)/Caddyfile' && grep -q 'max_size 17MiB' '$(D)/Caddyfile' && grep -q 'respond 404' '$(D)/Caddyfile' && grep -q 'Strict-Transport-Security' '$(D)/Caddyfile' && grep -q 'tls /certs/cert.pem /certs/key.pem' '$(D)/Caddyfile'"
check "Caddyfile : pas de journal d'accès, pas de rewrite/uri" sh -c "! grep -Eq '^\s*(log_name|output|uri |rewrite|handle_path|strip_prefix)' '$(D)/Caddyfile'"
check "Caddyfile : site https://203.0.113.7" grep -q '^https://203.0.113.7 {' "$(D)/Caddyfile"
check "curl health : connect-to local, -k en auto-signé" grep -q -- '-fsSk .*--connect-to ::127.0.0.1:443' "$S/curl.log"

echo "== idempotence"
cp "$(D)/server.env" "$E/env.1"; cp "$(D)/docker-compose.yml" "$E/compose.1"; cp "$(D)/Caddyfile" "$E/caddy.1"; cp "$(D)/install.state" "$E/state.1"
run --instance iptv --tls selfsigned --host 203.0.113.7,sync.example.net
check "2e exécution : ok, code 0" test "$RC" = 0
check "adminToken null + message explicite" pyj 'd["ok"] and d["adminToken"] is None and "déjà" in d["message"]'
check "jeton non régénéré : server.env identique" cmp -s "$(D)/server.env" "$E/env.1"
check "compose / Caddyfile / state identiques" sh -c "cmp -s '$(D)/docker-compose.yml' '$E/compose.1' && cmp -s '$(D)/Caddyfile' '$E/caddy.1' && cmp -s '$(D)/install.state' '$E/state.1'"
check "empreinte inchangée" pyj "d['tlsFingerprint']=='$FP'"
check "relance sans options reprend la configuration" sh -c "cd '$E' && env -i PATH='$E/bin' W3C_ROOT='$R' SHIM_STATE='$S' W3C_HEALTH_RETRIES=2 W3C_HEALTH_DELAY=0 sh '$INSTALL' --instance iptv >'$E/out2' 2>/dev/null && grep -q '\"adminToken\":null' '$E/out2'"

echo "== status / mise à jour / désinstallation"
run --instance iptv --status
check "status : ok, running, healthy" pyj 'd["ok"] and d["action"]=="status" and d["running"] is True and d["healthy"] is True and d["adminToken"] is None'
echo "donnée" > "$(D)/data/marker"
run --instance iptv --upgrade --image ghcr.io/svax974/web3c-sync:2.0.0
check "upgrade : ok, jeton null, action=upgrade" pyj 'd["ok"] and d["action"]=="upgrade" and d["adminToken"] is None'
check "upgrade : données conservées" test -f "$(D)/data/marker"
check "upgrade : server.env (hash) inchangé" cmp -s "$(D)/server.env" "$E/env.1"
check "upgrade : pull de la nouvelle image" grep -q 'pull ghcr.io/svax974/web3c-sync:2.0.0' "$S/docker.log"
check "upgrade : l'état retient la nouvelle image" grep -q 'image_requested=ghcr.io/svax974/web3c-sync:2.0.0' "$(D)/install.state"
cp "$(D)/docker-compose.yml" "$E/compose.up"
touch "$S/health_fail"
run --instance iptv --upgrade --image ghcr.io/svax974/web3c-sync:3.0.0
check "upgrade en échec de santé : HEALTH_FAILED, code != 0" sh -c "[ $RC -ne 0 ] && grep -q '\"error\":\"HEALTH_FAILED\"' '$E/out'"
check "upgrade en échec : ancienne version restaurée" sh -c "cmp -s '$(D)/docker-compose.yml' '$E/compose.up' && grep -q 'image_requested=ghcr.io/svax974/web3c-sync:2.0.0' '$(D)/install.state'"
rm -f "$S/health_fail"
run --instance iptv --uninstall
check "uninstall : ok, données conservées, config retirée" sh -c "[ $RC -eq 0 ] && [ -f '$(D)/data/marker' ] && [ ! -f '$(D)/server.env' ] && [ ! -f '$(D)/docker-compose.yml' ] && [ ! -d '$(D)/certs' ]"
check "uninstall : conteneurs arrêtés (compose down)" grep -q ' down ' "$S/docker.log"
run --instance iptv --uninstall --purge-data
check "uninstall --purge-data : tout supprimé" sh -c "[ $RC -eq 0 ] && [ ! -e '$(D)' ]"
run --instance iptv --status
check "status sans installation : NOT_INSTALLED" sh -c "[ $RC -ne 0 ] && grep -q NOT_INSTALLED '$E/out'"

echo "== échecs propres"
fresh; echo "0.0.0.0:443" > "$S/listen"
run --instance iptv --tls selfsigned --host 203.0.113.7
check "port 443 occupé : PORTS_BUSY, code != 0" sh -c "[ $RC -ne 0 ] && grep -q '\"error\":\"PORTS_BUSY\"' '$E/out'"
check "ports occupés : rien n'a été écrit ni lancé" sh -c "[ ! -e '$R/opt' ] && ! grep -q ' up ' '$S/docker.log' 2>/dev/null"
fresh; echo "[::]:80" > "$S/listen"
run --instance iptv --tls selfsigned --host 203.0.113.7
check "port 80 occupé (IPv6) : PORTS_BUSY" grep -q '"error":"PORTS_BUSY"' "$E/out"
fresh
run --nodocker --instance iptv --tls selfsigned --host 203.0.113.7
check "docker absent : DOCKER_MISSING, rien écrit" sh -c "[ $RC -ne 0 ] && grep -q '\"error\":\"DOCKER_MISSING\"' '$E/out' && [ ! -e '$R/opt' ]"
check "docker absent : jamais d'installation silencieuse" sh -c "! grep -qi 'apt-get' '$E/err' || grep -q -- '--install-docker' '$E/err'"
fresh; touch "$S/docker_down"
run --instance iptv --tls selfsigned --host 203.0.113.7
check "démon arrêté : DOCKER_DAEMON" grep -q '"error":"DOCKER_DAEMON"' "$E/out"
fresh
for bad_inst in 'prod' 'iptv;rm -rf /' '' '../iptv'; do
  run --instance "$bad_inst" --tls selfsigned --host 203.0.113.7
  check "instance invalide '$bad_inst' : INVALID_INSTANCE, code != 0" sh -c "[ $RC -ne 0 ] && grep -q '\"error\":\"INVALID_INSTANCE\"' '$E/out' && [ ! -e '$R/opt' ]"
done
run --instance iptv --tls selfsigned
check "selfsigned sans --host : INVALID_ARG" grep -q '"error":"INVALID_ARG"' "$E/out"
run --instance iptv --tls selfsigned --host '1.2.3.4;id'
check "--host avec métacaractères refusé" grep -q '"error":"INVALID_ARG"' "$E/out"
run --instance iptv --tls 'domain=a.b"c.org'
check "domaine avec guillemet refusé" grep -q '"error":"INVALID_ARG"' "$E/out"
run --instance iptv --tls selfsigned --host 1.2.3.4 --dir '/opt/x/../etc'
check "--dir avec .. refusé" grep -q '"error":"INVALID_ARG"' "$E/out"
run --instance iptv --tls selfsigned --host 1.2.3.4 --image 'x y'
check "image invalide refusée" grep -q '"error":"INVALID_ARG"' "$E/out"
touch "$S/pull_fail"; run --instance iptv --tls selfsigned --host 1.2.3.4
check "pull impossible : PULL_FAILED" grep -q '"error":"PULL_FAILED"' "$E/out"
rm -f "$S/pull_fail"
fresh; touch "$S/health_fail"
run --instance iptv --tls selfsigned --host 203.0.113.7
check "santé KO : HEALTH_FAILED, code != 0" sh -c "[ $RC -ne 0 ] && grep -q '\"error\":\"HEALTH_FAILED\"' '$E/out'"
check "échec : aucun jeton dans stdout/stderr" sh -c "! grep -Eq '[0-9a-f]{64}' '$E/out' '$E/err' || ! grep -q adminToken '$E/out'"

echo "== mode domaine (Let's Encrypt simulé : seul le fichier Caddy est vérifié)"
fresh
run --instance banking --tls domain=sync.example.org
check "DNS non résolu : DNS_UNRESOLVED" grep -q '"error":"DNS_UNRESOLVED"' "$E/out"
echo "sync.example.org 198.51.100.9" > "$S/dns"
run --instance banking --tls domain=sync.example.org --email admin@example.org
check "domaine : ok, url, pas d'empreinte" pyj 'd["ok"] and d["url"]=="https://sync.example.org" and d["tlsFingerprint"] is None and d["adminToken"] is not None'
check "Caddyfile domaine : site nu, e-mail, pas de tls manuel, pas de certs" sh -c "grep -q '^sync.example.org {' '$(D banking)/Caddyfile' && grep -q 'email admin@example.org' '$(D banking)/Caddyfile' && ! grep -q '^\s*tls /certs' '$(D banking)/Caddyfile' && [ ! -e '$(D banking)/certs/cert.pem' ]"
check "domaine : health vérifié SANS -k (validation du certificat)" sh -c "! grep -q -- '-k' '$S/curl.log'"
echo "banking sur 80/443 déjà occupé par ses propres conteneurs : relance acceptée"
touch "$S/running"; echo "0.0.0.0:443" > "$S/listen"
run --instance banking --tls domain=sync.example.org --email admin@example.org
check "relance avec nos propres conteneurs qui tiennent 443" pyj 'd["ok"]'

echo
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -s sh "$INSTALL" "$HERE/shims/"* "$0"; then ok "shellcheck"; else bad "shellcheck"; fi
else
  echo "  (shellcheck absent : non exécuté)"
fi
echo "Résultat : $PASS ok, $FAILS échec(s)"
[ "$FAILS" = 0 ]
