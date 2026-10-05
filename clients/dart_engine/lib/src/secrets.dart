import 'dart:convert';

import 'package:web3c_sync/web3c_sync.dart';

/// Where the credentials of the vault live: group id, server, group key,
/// device key, admin token. Backed by the OS keychain / keystore in the apps
/// (the app writes the 3-method adapter over its plugin of choice). **Never**
/// Hive, never synchronised, never logged.
abstract class SyncSecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// In-memory [SyncSecretStore] for tests.
class MemorySyncSecretStore implements SyncSecretStore {
  final values = <String, String>{};
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async => values[key] = value;
  @override
  Future<void> delete(String key) async => values.remove(key);
}

/// Names of the entries of a [SyncSecretStore] that belong to a pairing, all
/// under one [prefix] (e.g. `web3c.` or `budget.sync.web3c.`). The names are
/// part of the apps' persisted data: changing a prefix orphans existing
/// pairings.
class SyncSecretKeys {
  const SyncSecretKeys(this.prefix);
  final String prefix;

  String get server => '${prefix}server';
  String get groupId => '${prefix}groupId';
  String get groupKey => '${prefix}groupKey';
  String get deviceSeed => '${prefix}deviceSeed';
  String get adminToken => '${prefix}adminToken';
  String get tlsFingerprint => '${prefix}tlsFingerprint';
  String get isOwner => '${prefix}isOwner';

  /// Every entry of a pairing, erased when the group is left or purged (a new
  /// pairing gets a new device key, hence [deviceSeed] is in the list).
  List<String> get pairing =>
      [server, groupId, groupKey, deviceSeed, adminToken, tlsFingerprint, isOwner];
}

/// The device key (Ed25519 seed) kept in a [SyncSecretStore] under [seedKey].
class SecretStoreDeviceKeyStore extends DeviceKeyStore {
  SecretStoreDeviceKeyStore(this._s, this.seedKey);
  final SyncSecretStore _s;
  final String seedKey;

  @override
  Future<DeviceKey?> load() async {
    final v = await _s.read(seedKey);
    return v == null
        ? null
        : DeviceKey.fromSeed(base64Url.decode(base64Url.normalize(v)));
  }

  @override
  Future<void> save(DeviceKey key) =>
      _s.write(seedKey, base64Url.encode(key.seed));

  @override
  Future<void> delete() => _s.delete(seedKey);
}
