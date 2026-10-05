import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:web3c_sync/src/crypto.dart';
import 'package:web3c_sync/src/device_key.dart';

void main() {
  final v = jsonDecode(File('../../spec/vectors/v1.json').readAsStringSync())
      as Map<String, dynamic>;

  test('version', () => expect(v['version'], protocolVersion));

  test('hkdf', () {
    final h = v['hkdf'] as Map<String, dynamic>;
    final k = deriveKeys(unb64(h['kg'] as String));
    expect(b64(k.enc), h['enc']);
    expect(b64(k.id), h['id']);
    expect(b64(k.name), h['name']);
  });

  test('docId', () {
    final d = v['docId'] as Map<String, dynamic>;
    final k = deriveKeys(unb64(v['hkdf']['kg'] as String));
    expect(docId(k.id, d['collection'] as String, d['logicalId'] as String),
        d['docId']);
  });

  test('padme', () {
    final p = v['padme'] as Map<String, dynamic>;
    final ins = (p['in'] as List).cast<int>();
    final outs = (p['out'] as List).cast<int>();
    expect([for (final i in ins) padme(i)], outs);
  });

  test('seal / open with fixed nonce', () async {
    final s = v['seal'] as Map<String, dynamic>;
    final k = deriveKeys(unb64(v['hkdf']['kg'] as String));
    final a = aad(s['instance'] as String, s['groupId'] as String,
        s['collection'] as String, s['docId'] as String);
    expect(b64(a), s['aad']);
    final plain = utf8.encode(s['plaintext'] as String);
    final env = await seal(k.enc, a, plain, nonce: unb64(s['nonce'] as String));
    expect(b64(env), s['envelope']);
    expect(await open(k.enc, a, unb64(s['envelope'] as String)), plain);
  });

  test('application document (with logical id k) and device name', () async {
    final k = deriveKeys(unb64(v['hkdf']['kg'] as String));
    final app = v['sealApp'] as Map<String, dynamic>;
    expect(docId(k.id, app['collection'] as String, app['logicalId'] as String),
        app['docId']);
    final a = aad(app['instance'] as String, app['groupId'] as String,
        app['collection'] as String, app['docId'] as String);
    final plain = utf8.encode(app['plaintext'] as String);
    expect(
        b64(await seal(k.enc, a, plain, nonce: unb64(app['nonce'] as String))),
        app['envelope']);
    final opened = jsonDecode(
            utf8.decode(await open(k.enc, a, unb64(app['envelope'] as String))))
        as Map<String, dynamic>;
    expect(opened['k'], app['logicalId']);

    final n = v['deviceName'] as Map<String, dynamic>;
    final na = aad(n['instance'] as String, n['groupId'] as String, '_name',
        n['devicePub'] as String);
    final nameEnv = await seal(k.name, na, utf8.encode(n['name'] as String),
        nonce: unb64(n['nonce'] as String));
    expect(b64(nameEnv), n['nameEnc']);
    expect(utf8.decode(await open(k.name, na, unb64(n['nameEnc'] as String))),
        n['name']);
  });

  test('request canonical + signature', () async {
    final r = v['request'] as Map<String, dynamic>;
    final body = utf8.encode(r['body'] as String);
    expect(bodyHash(body), r['bodyHash']);
    final canon = canonicalRequest(
      method: r['method'] as String,
      pathQuery: r['path'] as String,
      timestamp: r['timestamp'] as String,
      nonce: r['nonce'] as String,
      bodyHash: bodyHash(body),
      instance: r['instance'] as String,
    );
    expect(utf8.decode(canon), r['canonical']);
    final key = await DeviceKey.fromSeed(unb64(r['seed'] as String));
    expect(key.publicKeyB64, r['pub']);
    expect(b64(await key.sign(canon)), r['signature']);
  });

  test('rating: pseudonym, text, digest', () {
    final r = v['rating'] as Map<String, dynamic>;
    final kUser = r['kUser'] == 'id'
        ? deriveKeys(unb64(v['hkdf']['kg'] as String)).id
        : unb64(r['kUser'] as String);
    final p =
        pseudonym(kUser, r['profileId'] as String, r['contentKey'] as String);
    expect(p, r['pseudonym']);
    final rating = r['r'] as num?;
    expect(ratingText(rating), r['ratingText']);
    final d = powDigest(r['contentKey'] as String, p, rating, r['n'] as int);
    expect(b64(d), r['digest']);
    expect(leadingZeroBits(d), greaterThanOrEqualTo(r['powBits'] as int));
    expect(
        powOk(r['contentKey'] as String, p, rating, r['n'] as int,
            r['powBits'] as int),
        isTrue);
  });

  test('ratingCases', () {
    final r = v['rating'] as Map<String, dynamic>;
    final p = r['pseudonym'] as String;
    for (final c in (v['ratingCases'] as List).cast<Map<String, dynamic>>()) {
      final rating = c['r'] as num?;
      expect(ratingText(rating), c['ratingText']);
      expect(
          b64(powDigest(r['contentKey'] as String, p, rating, c['n'] as int)),
          c['digest']);
    }
  });

  test('ratingText never "7.0"', () {
    expect(ratingText(7.0), '7');
    expect(ratingText(7), '7');
    expect(ratingText(7.5), '7.5');
    expect(ratingText(0.0), '0');
    expect(ratingText(-0.0), '0');
    expect(ratingText(1e-7), '0.0000001');
    expect(ratingText(1.5e-7), '0.00000015');
    expect(ratingText(null), 'null');
  });

  test('solvePow / solvePowAsync agree', () async {
    final r = v['rating'] as Map<String, dynamic>;
    final k = r['contentKey'] as String, p = r['pseudonym'] as String;
    final n = solvePow(k, p, 7.5, 8);
    expect(powOk(k, p, 7.5, n, 8), isTrue);
    expect(await solvePowAsync(k, p, 7.5, 8, yieldEvery: 7), n);
  });
}
