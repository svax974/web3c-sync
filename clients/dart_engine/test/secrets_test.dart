import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

void main() {
  test('SyncSecretKeys: names are prefix + fixed suffix, pairing lists them all', () {
    const k = SyncSecretKeys('web3c.');
    expect(k.server, 'web3c.server');
    expect(k.groupId, 'web3c.groupId');
    expect(k.groupKey, 'web3c.groupKey');
    expect(k.deviceSeed, 'web3c.deviceSeed');
    expect(k.adminToken, 'web3c.adminToken');
    expect(k.tlsFingerprint, 'web3c.tlsFingerprint');
    expect(k.isOwner, 'web3c.isOwner');
    expect(k.pairing.toSet(), {
      'web3c.server',
      'web3c.groupId',
      'web3c.groupKey',
      'web3c.deviceSeed',
      'web3c.adminToken',
      'web3c.tlsFingerprint',
      'web3c.isOwner',
    });
    expect(const SyncSecretKeys('budget.sync.web3c.').groupKey,
        'budget.sync.web3c.groupKey');
  });

  test('MemorySyncSecretStore read / write / delete', () async {
    final s = MemorySyncSecretStore();
    expect(await s.read('a'), isNull);
    await s.write('a', '1');
    expect(await s.read('a'), '1');
    await s.delete('a');
    expect(await s.read('a'), isNull);
  });

  test('the device key lives under seedKey and is created once', () async {
    final s = MemorySyncSecretStore();
    final store = SecretStoreDeviceKeyStore(s, 'p.deviceSeed');
    expect(await store.load(), isNull);
    final k1 = await store.loadOrCreate();
    expect(s.values.keys, ['p.deviceSeed']);
    final k2 = await SecretStoreDeviceKeyStore(s, 'p.deviceSeed').loadOrCreate();
    expect(k2.publicKeyB64, k1.publicKeyB64);
    await store.delete();
    expect(s.values, isEmpty);
    final k3 = await store.loadOrCreate();
    expect(k3.publicKeyB64, isNot(k1.publicKeyB64));
  });

  test('a stored seed round-trips to the same identity', () async {
    final key = await DeviceKey.generate();
    final s = MemorySyncSecretStore();
    final store = SecretStoreDeviceKeyStore(s, 'seed');
    await store.save(key);
    expect((await store.load())!.publicKeyB64, key.publicKeyB64);
  });
}
