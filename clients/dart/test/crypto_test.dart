import 'dart:convert';

import 'package:test/test.dart';
import 'package:web3c_sync/src/crypto.dart';
import 'package:web3c_sync/src/group_link.dart';

void main() {
  final keys = deriveKeys(List.filled(32, 7));
  final a = aad('iptv', 'g', 'progress', 'd');
  final plain = utf8.encode('{"v":1,"u":1,"k":"x","d":{}}');

  test('round trip', () async {
    final env = await seal(keys.enc, a, plain);
    expect(await open(keys.enc, a, env), plain);
  });

  test('nonce is random', () async {
    expect(await seal(keys.enc, a, plain), isNot(await seal(keys.enc, a, plain)));
  });

  test('tampering rejected', () async {
    final env = await seal(keys.enc, a, plain);
    for (final i in [0, 1, 13, env.length - 1]) {
      final bad = List<int>.from(env)..[i] ^= 1;
      await expectLater(open(keys.enc, a, bad), throwsA(isA<DecryptException>()));
    }
    await expectLater(open(keys.enc, a, env.sublist(0, 20)),
        throwsA(isA<DecryptException>()));
  });

  test('wrong key rejected', () async {
    final env = await seal(keys.enc, a, plain);
    final other = deriveKeys(List.filled(32, 8));
    await expectLater(open(other.enc, a, env), throwsA(isA<DecryptException>()));
  });

  test('AAD bound to instance, group, collection, doc', () async {
    final env = await seal(keys.enc, a, plain);
    for (final bad in [
      aad('banking', 'g', 'progress', 'd'),
      aad('iptv', 'h', 'progress', 'd'),
      aad('iptv', 'g', 'ratings', 'd'),
      aad('iptv', 'g', 'progress', 'e'),
    ]) {
      await expectLater(open(keys.enc, bad, env), throwsA(isA<DecryptException>()));
    }
  });

  test('padding hides length and is stripped', () async {
    for (final n in [0, 1, 5, 15, 16, 100, 1000]) {
      final p = List<int>.generate(n, (i) => i % 251 + 1);
      final env = await seal(keys.enc, a, p);
      expect(env.length, 1 + 12 + padme(n + 1) + 16);
      expect(await open(keys.enc, a, env), p);
    }
    // Different lengths in the same padme bucket give same envelope size.
    expect((await seal(keys.enc, a, List.filled(1001, 1))).length,
        (await seal(keys.enc, a, List.filled(1020, 1))).length);
  });

  test('payload ending in 0x00 / 0x80 survives', () async {
    for (final p in [
      [0, 0, 0],
      [0x80],
      [1, 0x80, 0],
    ]) {
      expect(await open(keys.enc, a, await seal(keys.enc, a, p)), p);
    }
  });

  test('GroupLink round trip', () {
    final link = GroupLink(
      server: 'https://sync.example.com:8443/x?y=1&z=2',
      instance: 'iptv',
      groupId: GroupLink.generateGroupId(),
      token: 'tok-en_1',
      groupKey: GroupLink.generateGroupKey(),
      tlsFingerprint: 'AB:CD',
    );
    final p = GroupLink.parse(link.format());
    expect(p.server, link.server);
    expect(p.groupId, link.groupId);
    expect(p.groupKey, link.groupKey);
    expect(p.tlsFingerprint, 'AB:CD');
    expect(GroupLink.parse(GroupLink(server: 's', instance: 'i',
        groupId: link.groupId, token: 't', groupKey: link.groupKey).format())
        .tlsFingerprint, isNull);
    expect(() => GroupLink.parse('http://x'), throwsFormatException);
    expect(() => GroupLink.parse('web3c-link:v1?s=a'), throwsFormatException);
    expect(link.groupKey.length, 32);
    expect(unb64(link.groupId).length, 16);
  });
}
