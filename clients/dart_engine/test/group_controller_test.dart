import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

SyncGroupController make(MemorySyncSecretStore secrets,
        {String instance = 'banking', void Function()? onChanged}) =>
    SyncGroupController(
      secrets: secrets,
      keys: const SyncSecretKeys('t.'),
      instance: instance,
      defaultServerUrl: 'http://127.0.0.1:1',
      deviceName: 'Test',
      onChanged: onChanged,
    );

String linkFor(String instance) => GroupLink(
      server: 'https://secret-host.example',
      instance: instance,
      groupId: GroupLink.generateGroupId(),
      token: 'TOKEN-SECRET',
      groupKey: GroupLink.generateGroupKey(),
    ).format();

void main() {
  test('a fresh controller has no group and load() on empty secrets keeps it so',
      () async {
    final c = make(MemorySyncSecretStore());
    await c.load();
    expect(c.hasGroup, isFalse);
    expect(c.client, isNull);
    expect(c.groupId, isNull);
    expect(c.devicePub, isNull);
    expect(c.isOwner, isFalse);
    expect(c.busy, isFalse);
    expect(c.error, isNull);
  });

  test('a link for another instance is refused with a clean message', () async {
    final secrets = MemorySyncSecretStore();
    var changes = 0;
    final c = make(secrets, onChanged: () => changes++);
    final link = linkFor('iptv');
    Object? thrown;
    try {
      await c.join(link);
    } catch (e) {
      thrown = e;
    }
    expect(thrown, isA<SyncEngineException>());
    final msg = (thrown as SyncEngineException).message;
    expect(msg, contains('another service'));
    for (final bad in ['secret-host', 'TOKEN-SECRET', 'web3c-link']) {
      expect(msg, isNot(contains(bad)));
      expect(c.error, isNot(contains(bad)));
    }
    expect(c.error, msg);
    expect(c.busy, isFalse);
    expect(c.hasGroup, isFalse);
    expect(changes, greaterThanOrEqualTo(2)); // busy on, busy off
    expect(secrets.values, isEmpty, reason: 'nothing persisted on failure');
  });

  test('a malformed link never echoes its content', () async {
    final c = make(MemorySyncSecretStore());
    const junk = 'web3c-link:v1?s=https%3A%2F%2Fsecret-host.example&k=KEYSECRET';
    final e = await c.join(junk).then<Object?>((_) => null, onError: (Object e) => e);
    expect(e, isA<SyncEngineException>());
    expect('$e', isNot(contains('KEYSECRET')));
    expect('$e', isNot(contains('secret-host')));
    expect(c.error, isNot(contains('KEYSECRET')));
  });

  test('createGroup on an unreachable server fails cleanly: no host in the error, nothing stored',
      () async {
    final secrets = MemorySyncSecretStore();
    final c = make(secrets);
    final e = await c
        .createGroup(serverUrl: 'http://127.0.0.1:1')
        .then<Object?>((_) => null, onError: (Object e) => e);
    expect(e, isA<SyncEngineException>());
    expect(c.error, 'server unreachable');
    expect(c.hasGroup, isFalse);
    expect(c.client, isNull);
    // only the device key may have been created; no pairing entry
    expect(secrets.values.keys.where((k) => k != 't.deviceSeed'), isEmpty);
  });

  test('requireServerUrl: a blank address is an error, not the default server',
      () async {
    final c = make(MemorySyncSecretStore());
    final e = await c
        .createGroup(serverUrl: '  ', requireServerUrl: true)
        .then<Object?>((_) => null, onError: (Object e) => e);
    expect((e as SyncEngineException).message, 'server address missing');
    expect(c.error, 'server address missing');
  });

  test('the error is cleared by the next operation', () async {
    final c = make(MemorySyncSecretStore());
    await c.join(linkFor('iptv')).then<void>((_) {}, onError: (Object _) {});
    expect(c.error, isNotNull);
    await c.load();
    expect(c.error, isNotNull, reason: 'load() is not an operation');
    await c.createJoinLink().then<void>((_) {}, onError: (Object _) {});
    expect(c.error, isNot(contains('another service')));
  });

  test('forgetLocally erases the pairing entries (device key included)', () async {
    final secrets = MemorySyncSecretStore();
    const keys = SyncSecretKeys('t.');
    for (final k in keys.pairing) {
      secrets.values[k] = 'x';
    }
    secrets.values['other.entry'] = 'keep';
    var changes = 0;
    final c = make(secrets, onChanged: () => changes++);
    await c.forgetLocally();
    expect(secrets.values.keys, ['other.entry']);
    expect(changes, 1);
  });
}
