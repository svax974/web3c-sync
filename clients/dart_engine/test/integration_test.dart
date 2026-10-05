// Two devices over the real Go server, through the generic pieces only:
// SyncGroupController, Web3CVaultTransport, SyncMetaStore, screenPage.
// Skipped unless WEB3C_SYNCD points to a built `syncd` binary.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

const _secret = 'PLAINTEXT-NEVER-ON-THE-SERVER-7Q';
const _instance = 'aiteam'; // allows any collection name

/// One device: its group controller, its transport and its bookkeeping.
class Dev {
  Dev(this.name, this.secrets, this.group, this.meta);
  final String name;
  final MemorySyncSecretStore secrets;
  final SyncGroupController group;
  final SyncMetaStore meta;
  late Web3CVaultTransport t = Web3CVaultTransport(group.client!);
}

void main() {
  final bin = Platform.environment['WEB3C_SYNCD'];
  if (bin == null || bin.isEmpty) {
    test('integration (WEB3C_SYNCD not set)', () {},
        skip: 'set WEB3C_SYNCD to the syncd binary');
    return;
  }

  late Process proc;
  late Directory tmp;
  late String url;
  final devices = <Dev>[];

  setUpAll(() async {
    tmp = Directory.systemTemp.createTempSync('web3c-engine-it');
    final s = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = s.port;
    await s.close();
    url = 'http://127.0.0.1:$port';
    proc = await Process.start(bin, [], environment: {
      'SYNC_INSTANCE': _instance,
      'SYNC_LISTEN': '127.0.0.1:$port',
      'SYNC_DB': '${tmp.path}/s.db',
      'SYNC_BLOB_DIR': '${tmp.path}/b',
      'SYNC_POW_BITS': '8',
    });
    proc.stdout.drain<void>();
    proc.stderr.drain<void>();
    final hc = http.Client();
    for (var i = 0; i < 100; i++) {
      try {
        if ((await hc.get(Uri.parse('$url/v1/health'))).statusCode == 200) break;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    hc.close();
  });

  tearDownAll(() async {
    for (final d in devices) {
      d.group.dispose();
    }
    proc.kill();
    await proc.exitCode;
    tmp.deleteSync(recursive: true);
  });

  Future<Dev> newDevice(String name, {String? link}) async {
    final secrets = MemorySyncSecretStore();
    final meta = SyncMetaStore.over(MemorySyncKeyValueStore());
    await meta.init();
    final group = SyncGroupController(
      secrets: secrets,
      keys: const SyncSecretKeys('it.'),
      instance: _instance,
      defaultServerUrl: url,
      deviceName: name,
    )..counterFloor = meta.counterFloor;
    if (link == null) {
      await group.createGroup();
    } else {
      await group.join(link);
    }
    final d = Dev(name, secrets, group, meta);
    devices.add(d);
    return d;
  }

  /// What an engine does for one pull, with the generic helpers.
  Future<ScreenedPage> pull(Dev d) async {
    final page = await d.t.changes(d.meta.cursor);
    final s = await screenPage(page, d.meta);
    await d.meta.setCursor(page.next);
    await d.meta.noteHighWater(page.next);
    return s;
  }

  late Dev a, b;

  test('A creates the group, pairs B by link, both are members', () async {
    a = await newDevice('Device A');
    expect(a.group.hasGroup, isTrue);
    expect(a.group.isOwner, isTrue);
    final link = await a.group.createJoinLink();
    b = await newDevice('Device B', link: link);
    expect(b.group.isOwner, isFalse);
    expect(b.group.groupId, a.group.groupId);
    final members = await a.group.members();
    expect(members, hasLength(2));
    expect(members.where((m) => m.owner), hasLength(1));
    // the secrets of a pairing are in the secret store, under the prefix
    expect(a.secrets.values.keys, containsAll(['it.groupId', 'it.groupKey', 'it.server', 'it.deviceSeed']));
    // a used link does not work twice
    final e = await newDevice('Device C', link: link)
        .then<Object?>((_) => null, onError: (Object e) => e);
    expect(e, isA<SyncEngineException>());
    expect('$e', isNot(contains(link.split('&k=').last)));
  });

  test('a transport read/write round trip between the two devices', () async {
    final r = await a.t.put('notes', 'n1', {'text': _secret},
        updatedAt: 1000, knownSeq: 0, knownCounter: 0);
    expect(r.written, isTrue);
    expect(r.record.counter, 1);
    final got = (await b.t.get('notes', 'n1'))!;
    expect(got.payload, {'text': _secret});
    expect(got.updatedAt, 1000);
    expect(got.counter, 1);
    expect(b.t.docId('notes', 'n1'), a.t.docId('notes', 'n1'));
  });

  test('the cursor, high-water mark and counters persist across a restart',
      () async {
    final s1 = await pull(b);
    expect(s1.accepted.map((p) => p.record.key), ['n1']);
    expect(s1.rolledBack, isEmpty);
    expect(b.meta.counterFloor('notes', b.t.docId('notes', 'n1')), 1);
    expect(b.meta.cursor, greaterThan(0));
    expect(b.meta.highWater, b.meta.cursor);
    // nothing new: an empty page, same cursor
    final before = b.meta.cursor;
    expect((await pull(b)).accepted, isEmpty);
    expect(b.meta.cursor, before);
  });

  test('last write wins on u, counters grow across devices', () async {
    // B writes a newer version, A an older one: A loses the merge.
    final nb = await b.t.put('notes', 'n1', {'text': 'B'},
        updatedAt: 3000, knownCounter: b.meta.counterFloor('notes', b.t.docId('notes', 'n1')) ?? 0);
    expect(nb.written, isTrue);
    expect(nb.record.counter, 2);
    final na = await a.t.put('notes', 'n1', {'text': 'A-old'}, updatedAt: 2000);
    expect(na.written, isFalse);
    expect(na.record.payload, {'text': 'B'});
    // a stale knownSeq falls back to read-merge-write, and counters keep growing
    final again = await a.t.put('notes', 'n1', {'text': 'A-new'},
        updatedAt: 4000, knownSeq: 1);
    expect(again.written, isTrue);
    expect(again.record.counter, 3);
  });

  test('a deletion is an authenticated marker, never a server tombstone', () async {
    await a.t.put('notes', 'n2', {'text': 'bye'}, updatedAt: 5000, knownSeq: 0);
    await pull(b);
    final d = await a.t.delete('notes', 'n2', updatedAt: 6000);
    expect(d.wasDeleted, isTrue);
    final s = await pull(b);
    final marker = s.accepted.singleWhere((p) => p.record.key == 'n2');
    expect(marker.record.deleted, isTrue);
    expect(marker.record.updatedAt, 6000);
    expect(s.tombstones, isEmpty);
    expect(await b.t.get('notes', 'n2'), isNull);
    // an older deletion does not beat a newer live version
    final kept = await b.t.delete('notes', 'n1', updatedAt: 1);
    expect(kept.wasDeleted, isFalse);
    // a newer write resurrects it
    final back = await b.t.put('notes', 'n2', {'text': 'back'}, updatedAt: 7000);
    expect(back.written, isTrue);
    expect((await a.t.get('notes', 'n2'))!.payload, {'text': 'back'});
  });

  test('a server tombstone (forged deletion) is surfaced as VaultDelete, never as a deletion',
      () async {
    await pull(b);
    await a.group.client!.deleteDoc('notes', 'n1',
        ifMatchSeq: (await a.t.get('notes', 'n1'))!.seq);
    final s = await pull(b);
    expect(s.tombstones, hasLength(1));
    expect(s.accepted, isEmpty);
    expect(await b.t.get('notes', 'n1'), isNull);
    // an authentic write replaces the tombstone (A kept its counter memory, as
    // an engine does: `c` continues instead of restarting at 1)
    await pull(a);
    final id = a.t.docId('notes', 'n1');
    await a.meta.noteCounter('notes', id, 3); // what A's own writes recorded
    final r = await a.t.put('notes', 'n1', {'text': 'alive'},
        updatedAt: 8000, knownCounter: a.meta.counterFloor('notes', id) ?? 0);
    expect(r.written, isTrue);
    expect((await b.t.get('notes', 'n1'))!.payload, {'text': 'alive'});
  });

  test('a document below the known counter floor comes back as rolled back',
      () async {
    await pull(b);
    final id = b.t.docId('notes', 'n1');
    final real = b.meta.counterFloor('notes', id)!;
    // this device claims to have seen a much higher counter than the server serves
    await b.meta.noteCounter('notes', id, real + 10);
    await a.t.put('notes', 'n1', {'text': 'touch'}, updatedAt: 9000);
    final s = await pull(b);
    expect(s.accepted.where((p) => p.record.key == 'n1'), isEmpty);
    final rb = s.rolledBack.single;
    expect(rb.floor, real + 10);
    expect(rb.counter, lessThan(rb.floor));
    // the memory is only raised, never lowered
    expect(b.meta.counterFloor('notes', id), real + 10);
    // legitimate restore of the server: forgetting the memory accepts it again
    await b.meta.forgetRollbackMemory();
    final again = await pull(b);
    expect(again.rolledBack, isEmpty);
    expect(again.accepted.map((p) => p.record.key), contains('n1'));
  });

  test('watch signals a change made by another device', () async {
    await pull(a);
    final got = Completer<int>();
    final sub = a.t.watch(a.meta.cursor).listen((s) {
      if (!got.isCompleted) got.complete(s);
    });
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final r = await b.t.put('notes', 'n3', {'text': 'live'}, updatedAt: 10000, knownSeq: 0);
    expect(await got.future.timeout(const Duration(seconds: 10)), greaterThan(0));
    expect(r.written, isTrue);
    await sub.cancel();
  });

  test('closing the transport does not close the controller\'s client', () async {
    await a.t.close();
    expect((await a.group.client!.members()), isNotEmpty);
    expect(await a.t.get('notes', 'n3'), isNotNull);
  });

  test('a restarted controller restores the same pairing from the secret store',
      () async {
    final again = SyncGroupController(
      secrets: a.secrets,
      keys: const SyncSecretKeys('it.'),
      instance: _instance,
      defaultServerUrl: url,
    );
    await again.load();
    expect(again.hasGroup, isTrue);
    expect(again.isOwner, isTrue);
    expect(again.groupId, a.group.groupId);
    expect(again.devicePub, a.group.devicePub);
    expect((await again.members()), hasLength(2));
    again.dispose();
  });

  test('the server never sees the plaintext', () async {
    final needles = [utf8.encode(_secret), utf8.encode('alive'), utf8.encode('notes_text')];
    var scanned = 0;
    for (final f in tmp.listSync(recursive: true).whereType<File>()) {
      final bytes = f.readAsBytesSync();
      scanned += bytes.length;
      for (final n in needles.take(1)) {
        expect(_contains(bytes, n), isFalse, reason: f.path);
      }
    }
    expect(scanned, greaterThan(0));
  });

  test('revoking B: B is refused, with a clean error', () async {
    final pub = b.group.devicePub!;
    await a.group.revoke(pub);
    expect(await a.group.members(), hasLength(1));
    final e = await b.t
        .changes(0)
        .then<Object?>((_) => null, onError: (Object e) => e);
    expect(e is UnauthorizedException || e is ForbiddenException, isTrue);
    expect(isRetryableSyncError(e!), isFalse);
    expect(describeSyncError(e), contains('access denied'));
  });

  test('leave and purge', () async {
    final link = await a.group.createJoinLink();
    final c = await newDevice('Device C', link: link);
    await c.group.leave();
    expect(c.group.hasGroup, isFalse);
    expect(c.secrets.values, isEmpty, reason: 'the pairing and the device key are forgotten');
    expect(await a.group.members(), hasLength(1));
    final gid = a.group.groupId!;
    await a.group.purgeGroup();
    expect(a.group.hasGroup, isFalse);
    expect(a.secrets.values, isEmpty);
    // the group is gone on the server: a fresh device cannot read it
    final probe = Web3CSyncClient(
        baseUrl: url,
        instance: _instance,
        deviceKey: await DeviceKey.generate(),
        groupId: gid,
        groupKey: GroupLink.generateGroupKey());
    await expectLater(probe.changes(0),
        throwsA(anyOf(isA<ForbiddenException>(), isA<NotFoundException>(), isA<UnauthorizedException>())));
    probe.close();
  });
}

bool _contains(List<int> hay, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= hay.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (hay[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
