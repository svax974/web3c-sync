import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:web3c_sync/src/crypto.dart' as c;
import 'package:web3c_sync/web3c_sync.dart';

const _inst = 'iptv';

void main() {
  linkErrorsDoNotLeakTheLink();
  late DeviceKey key;
  late String gid;
  late Uint8List kg;
  late c.DerivedKeys keys;
  final fixedNow = DateTime.utc(2026, 1, 1);

  setUp(() async {
    key = await DeviceKey.generate();
    gid = GroupLink.generateGroupId();
    kg = Uint8List.fromList(GroupLink.generateGroupKey());
    keys = c.deriveKeys(kg);
  });

  Web3CSyncClient client(http.Client hc,
          {int? Function(String, String)? floor,
          String base = 'https://x.test'}) =>
      Web3CSyncClient(
        baseUrl: base,
        instance: _inst,
        deviceKey: key,
        groupId: gid,
        groupKey: kg,
        httpClient: hc,
        counterFloor: floor,
        clock: () => fixedNow,
      );

  Future<String> envFor(
      String coll, String logical, Map<String, Object?> body) async {
    final id = c.docId(keys.id, coll, logical);
    return c.b64(await c.seal(
        keys.enc, c.aad(_inst, gid, coll, id), utf8.encode(jsonEncode(body))));
  }

  http.Response json(Object o, [int status = 200]) =>
      http.Response(jsonEncode(o), status,
          headers: {'content-type': 'application/json'});

  Future<Map<String, Object?>> item(String coll, String logical,
          Map<String, Object?> body, int seq) async =>
      {
        'collection': coll,
        'docId': c.docId(keys.id, coll, logical),
        'seq': seq,
        'deleted': false,
        'updatedAt': 1,
        'env': await envFor(coll, logical, body),
      };

  group('plaintext rules', () {
    test('document without c is Undecryptable with an explicit error',
        () async {
      final it = await item('p', 'a', {'v': 1, 'u': 5, 'k': 'a', 'd': 1}, 1);
      final cl = client(MockClient((_) async => json({
            'items': [it],
            'next': 1,
            'more': false
          })));
      final page = await cl.changes(0);
      final u = page.items.single as Undecryptable;
      expect(u.error, isA<InvalidDocumentException>());
      expect(u.error.toString(), contains('"c"'));
    });

    test('c must be an integer >= 1', () async {
      for (final bad in [0, -1, 1.5, '2', null]) {
        final it = await item(
            'p', 'a', {'v': 1, 'u': 5, 'c': bad, 'k': 'a', 'd': 1}, 1);
        final cl = client(MockClient((_) async => json({
              'items': [it],
              'next': 1,
              'more': false
            })));
        expect((await cl.changes(0)).items.single, isA<Undecryptable>(),
            reason: '$bad');
      }
    });

    test('u beyond now + 5 min is clamped; raw value kept', () async {
      final now = fixedNow.millisecondsSinceEpoch;
      final far = now + 3600 * 1000;
      final it =
          await item('p', 'a', {'v': 1, 'u': far, 'c': 1, 'k': 'a', 'd': 1}, 1);
      final ok = await item(
          'p', 'b', {'v': 1, 'u': now + 1000, 'c': 1, 'k': 'b', 'd': 1}, 2);
      final cl = client(MockClient((_) async => json({
            'items': [it, ok],
            'next': 2,
            'more': false
          })));
      final page = await cl.changes(0);
      final a = page.items[0] as DocChange, b = page.items[1] as DocChange;
      expect(a.updatedAt, now + 300000);
      expect(a.rawUpdatedAt, far);
      expect(b.updatedAt, now + 1000);
      expect(b.rawUpdatedAt, now + 1000);
    });

    test('del marker is exposed; payload null', () async {
      final it = await item(
          'p', 'a', {'v': 1, 'u': 5, 'c': 2, 'k': 'a', 'del': true}, 1);
      final cl = client(MockClient((_) async => json({
            'items': [it],
            'next': 1,
            'more': false
          })));
      final d = (await cl.changes(0)).items.single as DocChange;
      expect(d.deleted, isTrue);
      expect(d.counter, 2);
      expect(d.record.payload, isNull);
    });

    test('putMarker writes {v,u,c,k,del} without d', () async {
      late Uint8List sent;
      final cl = client(MockClient((req) async {
        if (req.method == 'PUT') {
          sent = req.bodyBytes;
          return json({'seq': 4});
        }
        throw StateError('unexpected ${req.method}');
      }));
      final seq =
          await cl.putMarker('p', 'a', updatedAt: 9, ifMatchSeq: 0, counter: 7);
      expect(seq, 4);
      final id = c.docId(keys.id, 'p', 'a');
      final plain = jsonDecode(utf8
              .decode(await c.open(keys.enc, c.aad(_inst, gid, 'p', id), sent)))
          as Map<String, dynamic>;
      expect(plain, {'v': 1, 'u': 9, 'c': 7, 'k': 'a', 'del': true});
    });
  });

  group('anti-rollback', () {
    test('c below the floor is RolledBack / RollbackException', () async {
      final it =
          await item('p', 'a', {'v': 1, 'u': 5, 'c': 2, 'k': 'a', 'd': 1}, 1);
      final id = c.docId(keys.id, 'p', 'a');
      final cl = client(
          MockClient((r) async => r.url.path.endsWith('/changes')
              ? json({
                  'items': [it],
                  'next': 1,
                  'more': false
                })
              : http.Response.bytes(c.unb64(it['env'] as String), 200,
                  headers: {'x-seq': '1'})),
          floor: (coll, d) => d == id ? 3 : null);
      final r = (await cl.changes(0)).items.single as RolledBack;
      expect([r.counter, r.floor], [2, 3]);
      expect(r.isAuthenticated, isFalse);
      await expectLater(cl.getDoc('p', 'a'), throwsA(isA<RollbackException>()));
      // equal to the floor is accepted
      final ok = client(
          MockClient((_) async => json({
                'items': [it],
                'next': 1,
                'more': false
              })),
          floor: (_, __) => 2);
      expect((await ok.changes(0)).items.single, isA<DocChange>());
    });

    test('a decreasing cursor raises RollbackException', () async {
      final cl = client(MockClient(
          (_) async => json({'items': [], 'next': 3, 'more': false})));
      await expectLater(cl.changes(10), throwsA(isA<RollbackException>()));
    });

    test('changesAll stops when next does not progress', () async {
      var calls = 0;
      final cl = client(MockClient((_) async {
        calls++;
        return json({'items': [], 'next': 5, 'more': true});
      }));
      final p = await cl.changesAll(5);
      expect(p.next, 5);
      expect(calls, 1);
    });

    test('changesAll has a page ceiling', () async {
      var calls = 0;
      final cl = client(MockClient((_) async {
        calls++;
        return json({'items': [], 'next': calls, 'more': true});
      }));
      await expectLater(
          cl.changesAll(0, maxPages: 20), throwsA(isA<ServerException>()));
      expect(calls, 20);
    });

    test('server tombstones are not authenticated', () {
      expect(const Tombstone('p', 'd', 1).isAuthenticated, isFalse);
    });
  });

  group('transport', () {
    test('http:// refused except on loopback', () {
      for (final u in [
        'http://example.com',
        'http://10.0.0.1:8080',
        'ftp://x',
        'http://localhost.evil.com',
      ]) {
        expect(() => client(MockClient((_) async => json({})), base: u),
            throwsArgumentError,
            reason: u);
        expect(() => CommunityClient(u, 8), throwsArgumentError, reason: u);
      }
      for (final u in [
        'http://127.0.0.1:1',
        'http://localhost:2',
        'http://[::1]:3',
        'https://example.com/',
      ]) {
        client(MockClient((_) async => json({})), base: u).close();
        CommunityClient(u, 8).close();
      }
    });

    test('redirects are not followed and a 3xx is a ServerException', () async {
      late http.BaseRequest seen;
      final cl = client(MockClient((req) async {
        seen = req;
        return http.Response('', 302, headers: {'location': 'https://evil/'});
      }));
      await expectLater(
          cl.info(),
          throwsA(
              isA<ServerException>().having((e) => e.status, 'status', 302)));
      expect(seen.followRedirects, isFalse);

      final com = CommunityClient('https://x.test', 0,
          httpClient: MockClient((req) async {
        seen = req;
        return http.Response('', 307);
      }));
      await expectLater(
          com.get('movie:tmdb:1'), throwsA(isA<ServerException>()));
      expect(seen.followRedirects, isFalse);
    });

    test('malformed TLS fingerprint fails closed', () {
      for (final fp in ['', 'zz', 'ABCD', '00' * 31, '${'0' * 63}g']) {
        expect(() => parseFingerprint(fp), throwsFormatException, reason: fp);
        expect(
            () => Web3CSyncClient(
                baseUrl: 'https://x.test',
                instance: _inst,
                deviceKey: key,
                tlsFingerprint: fp),
            throwsFormatException,
            reason: fp);
      }
      expect(parseFingerprint('00' * 32).length, 32);
    });
  });

  group('community vote', () {
    test('body carries t, PoW covers it; 409 is Conflict', () async {
      late Map<String, dynamic> body;
      final com = CommunityClient('https://x.test', 8,
          clock: () => DateTime.fromMillisecondsSinceEpoch(1760000000123),
          httpClient: MockClient((req) async {
            body = jsonDecode(req.body) as Map<String, dynamic>;
            return json({'error': 'conflict'}, 409);
          }));
      await expectLater(com.vote('movie:tmdb:603', 'p1', keys.rating, 7.5),
          throwsA(isA<ConflictException>()));
      expect(body.keys.toSet(), {'p', 'r', 't', 'n'});
      expect(body['t'], 1760000000);
      expect(body['p'], c.pseudonym(keys.rating, 'p1', 'movie:tmdb:603'));
      expect(
          c.powOk(
              'movie:tmdb:603', body['p'] as String, 7.5, body['n'] as int, 8,
              t: 1760000000),
          isTrue);
    });

    test('contentKey format is enforced', () async {
      final com = CommunityClient('https://x.test', 0,
          httpClient: MockClient((_) async => json({})));
      for (final k in [
        'movie:tmdb:',
        'movie:tmdb:1234567890',
        'game:tmdb:1',
        'movie:imdb:1',
        'movie:tmdb:1/../x',
        'Movie:tmdb:1',
      ]) {
        await expectLater(com.vote(k, 'p', keys.rating, 5), throwsArgumentError,
            reason: k);
      }
    });
  });
}

// A malformed pairing link must never echo the link (it carries the group key).
// Appended after the existing tests; kept in this file to share its imports.
void linkErrorsDoNotLeakTheLink() {
  test('GroupLink.parse errors never contain the link', () {
    const secret = 'SUPERSECRETKEYMATERIAL';
    for (final bad in [
      'web3c-link:v1?s=https://x&i=iptv&g=short&t=tok&k=$secret',
      'not-a-link-$secret',
      'web3c-link:v1?s=https://x&i=iptv&g=AAAAAAAAAAAAAAAAAAAAAA&t=&k=$secret',
    ]) {
      try {
        GroupLink.parse(bad);
        fail('should have thrown');
      } on FormatException catch (e) {
        expect(e.toString(), isNot(contains(secret)));
        expect(e.source, isNull);
      }
    }
  });
}
