# web3c_sync_installer

Installe et gère le « serveur personnel » web3c-sync sur le serveur de
l'utilisateur, **par SSH**, en Dart pur (`dartssh2`, donc aussi iOS/tvOS/Android/
desktop). Il transporte `deploy/install/install.sh` + ses modèles (embarqués,
`lib/src/script_bundle.g.dart`, régénérés par `dart run tool/gen_bundle.dart` ;
`test/bundle_test.dart` échoue en cas de dérive).

```dart
final installer = Web3CInstaller();
final res = await installer.install(
  InstallRequest(
    host: '203.0.113.7', username: 'alice',
    auth: PasswordAuth(password),            // saisi dans le dialogue, pour CET appel
    sudo: SudoMode.password,                 // sudo -S, mot de passe sur stdin
    instance: SyncInstance.iptv,
    tls: const TlsMode.selfSigned(['203.0.113.7']),   // ou TlsMode.domain('sync.exemple.org')
    image: 'ghcr.io/svax974/web3c-sync@sha256:…',
    expectedHostKeySha256: savedHostKeyOrNull,        // empreinte confirmée avant
  ),
  onHostKey: (info) async => await ui.confirm(info.type, info.sha256Fingerprint), // OBLIGATOIRE
  onProgress: (p) => log(p.message),                   // assaini
);
final cfg = res.toServerConfig();   // serverUrl, adminToken?, tlsFingerprint?, instance
// -> Web3CGroupController.createGroup(serverUrl: cfg.serverUrl, adminToken: cfg.adminToken,
//                                      tlsFingerprint: cfg.tlsFingerprint)
```

`status`, `upgrade`, `uninstall` suivent le même schéma. Erreurs typées :
`HostKeyRejected`, `HostKeyChanged`, `AuthFailed`, `SudoFailed`, `DockerMissing`,
`PortsBusy`, `HealthCheckFailed`, `ScriptFailed(code, message)`, plus
`InvalidRequest` (champ seul, jamais la valeur) et `ConnectionFailed`.

## Empreinte d'hôte (TOFU)
Format `SHA256:<base64>` (celui de `ssh-keygen -lf`). Sans `expectedHostKeySha256`,
`onHostKey` décide (exception du callback = refus). Avec une empreinte attendue :
identique = accepté sans question ; différente = `HostKeyChanged`, **sans** appeler
le callback. L'empreinte est vérifiée avant toute authentification : un refus
n'exécute rien. L'appelant mémorise `InstallResult.hostKeySha256`. MD5 : non
disponible (dartssh2 n'expose que SHA-256), `md5` est donc null.

## Hygiène des secrets
- Mot de passe SSH / sudo / clé / passphrase : conservés dans des `Secret`
  (octets) **écrasés à la fin de l'appel** (`finally`) ; un `InstallRequest` ne
  se réutilise pas (`StateError`). **Limite Dart** : la `String` d'origine fournie
  par l'appelant et la `String` transitoire que dartssh2 exige à l'authentification
  sont immuables et restent en mémoire jusqu'au ramasse-miettes ; elles ne peuvent
  pas être effacées.
- Le mot de passe sudo va sur le **stdin** de `sudo -S -p '' -k`, jamais dans une
  ligne de commande distante. `remoteEnvironment` apparaît, lui, en ligne de
  commande : n'y mettez jamais de secret.
- Progression et erreurs passent par un assainisseur : secrets connus masqués, toute
  chaîne de 64 hexadécimaux (hors `sha256:`) masquée, caractères de contrôle retirés,
  longueur bornée. Les exceptions ne contiennent jamais l'entrée brute.
- Le jeton admin n'existe que dans `InstallResult.adminToken` (première installation
  seulement) ; `toString()` le masque ; le paquet ne l'imprime jamais. Stockez-le
  chiffré (Keychain/Keystore), ne le synchronisez jamais (plan §7).
- Pas de SFTP : les fichiers sont écrits par `cat` sur stdin dans un dossier
  `mktemp -d` (0700), supprimé en fin d'opération.

## Tests
`dart test` : unitaires (parsing, assainissement, TOFU, sentinelles) avec un faux
transport, et `ssh_integration_test.dart` : **vrai SSH** contre un `sshd` OpenSSH
non privilégié local (clé publique), script embarqué, faux docker/curl/ss
(`deploy/install/test/shims`) et openssl réel. Il se saute proprement si sshd ne
peut pas démarrer.

**Non vérifié** : l'authentification par **mot de passe** réussie (sshd non root sans
PAM ; dartssh2 est client seul, pas de serveur factice) — seuls le refus de mot de
passe et l'usage de `sudo -S` via un faux transport sont testés, ainsi que le
keyboard-interactive (non testé du tout) ; un vrai `sudo` ; un vrai Docker et Let's
Encrypt ; tvOS/iOS ; hôtes dont le shell de connexion n'est pas POSIX (fish).
