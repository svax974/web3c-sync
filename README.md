# web3c-sync

Serveur de synchronisation **chiffré de bout en bout** et clients associés,
partagés par VxIPTV (Flutter + tvOS), le module IPTV d'AICompanion,
SoSimpleBank et AICompanion.

- `spec/PROTOCOL.md` — protocole v1 et chiffrement (source de vérité).
- `spec/vectors/v1.json` — vecteurs de test que tout client doit reproduire.
- `server/` — serveur Go (SQLite, une instance par usage : `iptv`, `banking`, `aiteam`).
- `clients/dart/`, `clients/swift/` — clients de référence.
- `deploy/` — fichiers de déploiement (le déploiement des domaines publics se fait
  par les rôles Ansible d'InfraManager).

Plan et décisions : `AICompanion/docs-project/plans/2026-10-05-sync-web3c-backends-design.md`.

## Serveur

```sh
cd server
go test ./...            # sur macOS récent : go test -ldflags=-linkmode=external ./...
go run ./cmd/genvectors > ../spec/vectors/v1.json   # régénère les vecteurs (déterministe)

SYNC_INSTANCE=iptv SYNC_DB=/tmp/s.db SYNC_BLOB_DIR=/tmp/blobs go run ./cmd/syncd
```

Configuration (variables d'environnement) : `SYNC_INSTANCE` (obligatoire),
`SYNC_LISTEN`, `SYNC_METRICS_LISTEN` (adresse privée, format Prometheus),
`SYNC_DB`, `SYNC_BLOB_DIR`, `SYNC_COLLECTIONS` (`*` = toutes),
`SYNC_ADMIN_TOKEN_SHA256` (si défini, la création de groupe exige ce jeton :
mode serveur personnel), `SYNC_COMMUNITY`, `SYNC_POW_BITS`, `SYNC_MAX_DOCS`,
`SYNC_MAX_BYTES_MIB`, `SYNC_MAX_DOC_KIB`, `SYNC_MAX_BLOB_MIB`,
`SYNC_WRITES_PER_MIN`, `SYNC_CREATES_PER_DAY`, `SYNC_VOTES_PER_MIN`,
`SYNC_RETENTION_DAYS`, `SYNC_TRUST_PROXY` + `SYNC_REAL_IP_HEADER`.

Le serveur n'écrit **aucune adresse IP** sur disque et ne journalise aucun contenu.
