import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';

/// Lets a test run code just before a request goes out (race injection).
class HookClient extends http.BaseClient {
  HookClient(this._inner);
  final http.Client _inner;
  Future<void> Function(http.BaseRequest)? before;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final h = before;
    if (h != null) await h(request);
    return _inner.send(request);
  }
}

Future<int> freePort() async {
  final s = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final p = s.port;
  await s.close();
  return p;
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
  const powBits = 8;

  Future<Web3CSyncClient> newClient(
    DeviceKey k, {
    String? gid,
    List<int>? kg,
    http.Client? hc,
  }) async =>
      Web3CSyncClient(
        baseUrl: url,
        instance: 'iptv',
        deviceKey: k,
        groupId: gid,
        groupKey: kg,
        httpClient: hc,
      );

  setUpAll(() async {
    tmp = Directory.systemTemp.createTempSync('web3c-sync-it');
    final port = await freePort();
    url = 'http://127.0.0.1:$port';
    proc = await Process.start(bin, [], environment: {
      'SYNC_INSTANCE': 'iptv',
      'SYNC_LISTEN': '127.0.0.1:$port',
      'SYNC_DB': '${tmp.path}/s.db',
      'SYNC_BLOB_DIR': '${tmp.path}/b',
      'SYNC_POW_BITS': '$powBits',
    });
    proc.stdout.drain<void>();
    proc.stderr.drain<void>();
    final hc = http.Client();
    for (var i = 0; i < 100; i++) {
      try {
        final r = await hc.get(Uri.parse('$url/v1/health'));
        if (r.statusCode == 200) break;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    hc.close();
  });

  tearDownAll(() {
    proc.kill();
    tmp.deleteSync(recursive: true);
  });

  late DeviceKey ownerKey, bKey, cKey;
  late Web3CSyncClient owner, b;
  late String gid;
  late List<int> kg;
  final hook = HookClient(http.Client());

  test('create group, pair a second device through a GroupLink', () async {
    ownerKey = await DeviceKey.generate();
    bKey = await DeviceKey.generate();
    owner = await newClient(ownerKey, hc: hook);
    gid = await owner.createGroup();
    kg = owner.groupKey!;
    expect((await owner.info()).instance, 'iptv');

    final link = GroupLink.parse((await owner.createJoinLink()).format());
    expect(link.groupId, gid);
    expect(link.groupKey, kg);
    b = Web3CSyncClient(
      baseUrl: link.server,
      instance: link.instance,
      deviceKey: bKey,
      groupId: link.groupId,
      groupKey: link.groupKey,
    );
    await b.join(link.token, 'Apple TV salon');
    // single use
    final c2 = await newClient(await DeviceKey.generate(), gid: gid, kg: kg);
    await expectLater(
        c2.join(link.token, 'x'), throwsA(isA<ForbiddenException>()));

    final ms = await owner.members();
    expect(ms.length, 2);
    expect(ms.firstWhere((m) => m.device == bKey.publicKeyB64).name,
        'Apple TV salon');
    expect(ms.firstWhere((m) => m.owner).device, ownerKey.publicKeyB64);
  });

  test('encrypted exchange between two devices', () async {
    final seq = await owner.putDoc(
        'progress', 'movie_1', {'pos': 12, 'dur': 100},
        updatedAt: 1000, ifMatchSeq: 0);
    final got = await b.getDoc('progress', 'movie_1');
    expect(got.payload, {'pos': 12, 'dur': 100});
    expect(got.logicalId, 'movie_1');
    expect(got.updatedAt, 1000);
    expect(got.seq, seq);
    await expectLater(
        b.getDoc('progress', 'nope'), throwsA(isA<NotFoundException>()));
  });

  test('stale If-Match gives Conflict with the current seq', () async {
    final cur = (await b.getDoc('progress', 'movie_1')).seq;
    await expectLater(
      owner.putDoc('progress', 'movie_1', {}, updatedAt: 1, ifMatchSeq: 0),
      throwsA(isA<ConflictException>().having((e) => e.currentSeq, 'seq', cur)),
    );
  });

  test('upsert resolves a 409 race (latest inner updatedAt wins)', () async {
    // Create baseline.
    await owner.putDoc('prefs', 'p', {'v': 'base'},
        updatedAt: 100, ifMatchSeq: 0);
    var fired = false;
    hook.before = (req) async {
      // Just before the owner's first PUT, B writes a newer version.
      if (!fired && req.method == 'PUT' && req.url.path.contains('/d/prefs/')) {
        fired = true;
        final cur = await b.getDoc('prefs', 'p');
        await b.putDoc('prefs', 'p', {'v': 'from-b'},
            updatedAt: 500, ifMatchSeq: cur.seq);
      }
    };
    // Owner's value is older than B's: B must win after the retry.
    final r =
        await owner.upsert('prefs', 'p', {'v': 'owner-old'}, updatedAt: 300);
    expect(fired, isTrue);
    hook.before = null;
    expect(r.payload, {'v': 'from-b'});
    expect((await owner.getDoc('prefs', 'p')).payload, {'v': 'from-b'});

    // A newer local value wins over remote and is written.
    final w = await owner.upsert('prefs', 'p', {'v': 'newest'}, updatedAt: 900);
    expect(w.payload, {'v': 'newest'});
    expect((await b.getDoc('prefs', 'p')).payload, {'v': 'newest'});

    // Custom merge.
    final m = await b.upsert('prefs', 'p', {'n': 1},
        updatedAt: 1000,
        merge: (l, r) => Versioned(
            {...(r.payload as Map), ...(l.payload as Map)}, l.updatedAt));
    expect(m.payload, {'v': 'newest', 'n': 1});

    // Bounded retries.
    hook.before = (req) async {
      if (req.method == 'PUT' && req.url.path.contains('/d/prefs/')) {
        final cur = await b.getDoc('prefs', 'p');
        await b.putDoc('prefs', 'p', {'x': 1},
            updatedAt: cur.updatedAt + 1, ifMatchSeq: cur.seq);
      }
    };
    await expectLater(
        owner.upsert('prefs', 'p', {'z': 1},
            updatedAt: 1 << 50, maxAttempts: 3),
        throwsA(isA<ConflictException>()));
    hook.before = null;
  });

  test('tombstone: 410, changes, re-creation', () async {
    final cur = await owner.getDoc('progress', 'movie_1');
    final ts =
        await owner.deleteDoc('progress', 'movie_1', ifMatchSeq: cur.seq);
    await expectLater(b.getDoc('progress', 'movie_1'),
        throwsA(isA<GoneException>().having((e) => e.seq, 'seq', ts)));
    final page = await b.changesAll(0);
    final id = owner.docIdFor('progress', 'movie_1');
    expect(
        page.items
            .whereType<Tombstone>()
            .any((t) => t.docId == id && t.seq == ts),
        isTrue);
    // upsert re-creates over the tombstone.
    final r =
        await owner.upsert('progress', 'movie_1', {'pos': 1}, updatedAt: 2000);
    expect(r.seq, greaterThan(ts));
    expect((await b.getDoc('progress', 'movie_1')).payload, {'pos': 1});
  });

  test('paginated changes', () async {
    for (var i = 0; i < 7; i++) {
      await owner.putDoc('lists', 'l$i', {'i': i},
          updatedAt: 10 + i, ifMatchSeq: 0);
    }
    final first = await b.changes(0, limit: 3);
    expect(first.items.length, 3);
    expect(first.more, isTrue);
    final all = await b.changesAll(0, pageSize: 3);
    expect(all.more, isFalse);
    final seqs = all.items.map((e) => e.seq).toList();
    expect(seqs, [...seqs]..sort());
    final lists = all.items
        .whereType<DocChange>()
        .where((d) => d.collection == 'lists')
        .map((d) => d.record.logicalId)
        .toSet();
    expect(lists, {for (var i = 0; i < 7; i++) 'l$i'});
    expect(all.items.whereType<Undecryptable>(), isEmpty);
    // Resume from the cursor: nothing new.
    expect((await b.changesAll(all.next)).items, isEmpty);
  });

  test('SSE live event and resume with since', () async {
    final since = (await b.info()).seq;
    final events = StreamController<SyncEvent>();
    final sub = b.stream(since).listen(events.add, onError: events.addError);
    final it = StreamIterator(events.stream);
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final seq = await owner.putDoc('favorites', 'f1', {'a': 1},
        updatedAt: 1, ifMatchSeq: 0);
    expect(await it.moveNext().timeout(const Duration(seconds: 5)), isTrue);
    expect(it.current.seq, seq);
    expect(it.current.collection, 'favorites');
    expect(it.current.docId, owner.docIdFor('favorites', 'f1'));
    expect(it.current.deleted, isFalse);
    await sub.cancel();
    await it.cancel();
  });

  test('blobs with range', () async {
    await owner.putBlob('blob1', utf8.encode('0123456789'));
    expect(utf8.decode(await b.getBlob('blob1')), '0123456789');
    expect(utf8.decode(await b.getBlob('blob1', rangeStart: 2, rangeEnd: 5)),
        '2345');
    await owner.deleteBlob('blob1');
    await expectLater(b.getBlob('blob1'), throwsA(isA<NotFoundException>()));
  });

  test('a device with the WRONG group key cannot decrypt', () async {
    cKey = await DeviceKey.generate();
    final wrong = Uint8List.fromList(List.filled(32, 9));
    final link = await owner.createJoinToken();
    final c = await newClient(cKey, gid: gid, kg: wrong);
    await c.join(link.token, 'intrus');
    // Names are unreadable for the owner too (K_name differs).
    expect(
        (await owner.members())
            .firstWhere((m) => m.device == cKey.publicKeyB64)
            .name,
        isNull);
    // Same doc under the wrong K_id is simply unknown; with the right docId the
    // envelope still fails to open.
    await expectLater(
        c.getDoc('progress', 'movie_1'), throwsA(isA<NotFoundException>()));
    final page = await c.changesAll(0);
    final docs = page.items.where((i) => i is! Tombstone).toList();
    expect(docs, isNotEmpty);
    expect(docs.every((i) => i is Undecryptable), isTrue);
    // Raw fetch with the right docId: decryption must fail.
    final good = await newClient(cKey, gid: gid, kg: kg);
    await expectLater(good.getDoc('progress', 'movie_1'), completes);
    c.close();
    good.close();
  });

  test('revocation: the second device loses access', () async {
    await b.info();
    await owner.revoke(bKey.publicKeyB64);
    await expectLater(b.info(), throwsA(isA<ForbiddenException>()));
    await expectLater(b.changes(0), throwsA(isA<ForbiddenException>()));
    // The owner cannot be revoked.
    await expectLater(
        owner.revoke(ownerKey.publicKeyB64), throwsA(isA<NotFoundException>()));
    // Non-members' streams end with a terminal error.
    await expectLater(b.stream(0).first, throwsA(isA<ForbiddenException>()));
  });

  test('a stranger without membership is refused; unsigned is 401', () async {
    final s = await newClient(await DeviceKey.generate(), gid: gid, kg: kg);
    await expectLater(s.info(), throwsA(isA<ForbiddenException>()));
    final raw = await http.get(Uri.parse('$url/v1/g/$gid/info'));
    expect(raw.statusCode, 401);
  });

  test('community ratings: vote + PoW + aggregate', () async {
    var tick = DateTime.now().millisecondsSinceEpoch;
    // Each call is one second later: a vote must be strictly newer than the
    // previous vote of the same pseudonym.
    final com = CommunityClient(url, powBits,
        clock: () => DateTime.fromMillisecondsSinceEpoch(tick += 1000));
    final kUser = deriveKeys(kg).rating;
    const key = 'movie:tmdb:603';
    await com.vote(key, 'profile-1', kUser, 8);
    await com.vote(key, 'profile-2', kUser, 4.5);
    var agg = await com.get(key);
    expect(agg.count, 2);
    expect(agg.sum, 12.5);
    // Revote replaces, null removes.
    await com.vote(key, 'profile-1', kUser, 7);
    await com.vote(key, 'profile-2', kUser, null);
    agg = (await com.query([key, 'movie:tmdb:1']))[key]!;
    expect(agg.count, 1);
    expect(agg.sum, 7);
    expect((await com.query(['movie:tmdb:1']))['movie:tmdb:1']!.count, 0);
    // Out of range -> BadRequest.
    await expectLater(com.vote(key, 'profile-1', kUser, 11),
        throwsA(isA<BadRequestException>()));
    // Insufficient PoW refused.
    final weak = CommunityClient(url, 0,
        clock: () => DateTime.fromMillisecondsSinceEpoch(tick += 1000));
    var refused = false;
    for (var i = 0; i < 40 && !refused; i++) {
      try {
        await weak.vote('movie:tmdb:$i', 'p', kUser, 5);
      } on ForbiddenException {
        refused = true;
      }
    }
    expect(refused, isTrue);
    // A vote older than (or equal to) the stored one is refused: replay.
    final old = CommunityClient(url, powBits,
        clock: () => DateTime.fromMillisecondsSinceEpoch(tick - 600 * 1000));
    await expectLater(old.vote(key, 'profile-1', kUser, 1),
        throwsA(isA<ConflictException>()));
    // Same instant as the stored vote: also 409.
    final same = CommunityClient(url, powBits,
        clock: () => DateTime.fromMillisecondsSinceEpoch(tick));
    await com.vote('movie:tmdb:7', 'p', kUser, 3);
    await expectLater(same.vote('movie:tmdb:7', 'p', kUser, 4),
        throwsA(isA<ConflictException>()));
    com.close();
    weak.close();
    old.close();
    same.close();
  });

  test('authenticated deletion marker round trip; counters increase', () async {
    final w = await owner.upsert('prefs', 'm1', {'a': 1}, updatedAt: 10);
    expect(w.counter, 1);
    final w2 = await owner.upsert('prefs', 'm1', {'a': 2}, updatedAt: 20);
    expect(w2.counter, 2);
    // putDoc without explicit counter reads the remote c.
    final s3 = await owner.putDoc('prefs', 'm1', {'a': 3},
        updatedAt: 30, ifMatchSeq: w2.seq);
    expect((await owner.getDoc('prefs', 'm1')).counter, 3);
    final seq =
        await owner.putMarker('prefs', 'm1', updatedAt: 40, ifMatchSeq: s3);
    final got = await owner.getDoc('prefs', 'm1');
    expect(got.deleted, isTrue);
    expect(got.payload, isNull);
    expect(got.counter, 4);
    expect(got.seq, seq);
    final page = await owner.changesAll(0);
    final id = owner.docIdFor('prefs', 'm1');
    final dc =
        page.items.whereType<DocChange>().firstWhere((d) => d.docId == id);
    expect(dc.deleted, isTrue);
    expect(dc.counter, 4);
    expect(dc.isAuthenticated, isTrue);
    // Rollback detection against a floor above the stored counter.
    final floored = Web3CSyncClient(
      baseUrl: url,
      instance: 'iptv',
      deviceKey: ownerKey,
      groupId: gid,
      groupKey: kg,
      counterFloor: (c, d) => d == id ? 9 : null,
    );
    await expectLater(
        floored.getDoc('prefs', 'm1'), throwsA(isA<RollbackException>()));
    final fp = await floored.changesAll(0);
    expect(fp.items.whereType<RolledBack>().single.floor, 9);
    floored.close();
  });

  test('purge group', () async {
    await owner.purgeGroup();
    await expectLater(owner.info(), throwsA(isA<ForbiddenException>()));
  });
}
