import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';

void main() {
  test('SSE reconnects with backoff and resumes from the last seq', () async {
    final urls = <String>[];
    final mock = MockClient.streaming((req, _) async {
      urls.add(req.url.toString());
      final n = urls.length;
      expect(req.headers['X-Signature'], isNotEmpty);
      if (n == 1) {
        return http.StreamedResponse(
          Stream.value(utf8.encode(': ping\n\nid: 5\nevent: change\n'
              'data: {"collection":"progress","docId":"d","seq":5,"deleted":false}\n\n')),
          200,
        );
      }
      if (n == 2) throw http.ClientException('boom');
      return http.StreamedResponse(
        Stream.value(utf8.encode('id: 6\nevent: change\n'
            'data: {"collection":"progress","docId":"d","seq":6,"deleted":true}\n\n')),
        200,
      );
    });
    final key = await DeviceKey.generate();
    final c = Web3CSyncClient(
      baseUrl: 'https://x.test',
      instance: 'iptv',
      deviceKey: key,
      groupId: GroupLink.generateGroupId(),
      groupKey: GroupLink.generateGroupKey(),
      httpClient: mock,
      sseBackoffMin: const Duration(milliseconds: 5),
      sseBackoffMax: const Duration(milliseconds: 20),
    );
    final evs = await c.stream(2).take(2).toList();
    expect([for (final e in evs) e.seq], [5, 6]);
    expect(evs[1].deleted, isTrue);
    expect(urls[0], endsWith('/stream?since=2'));
    expect(urls[1], endsWith('/stream?since=5'));
    expect(urls[2], endsWith('/stream?since=5'));
  });

  test('401 on the stream is terminal', () async {
    final mock = MockClient.streaming((req, _) async => http.StreamedResponse(
        Stream.value(utf8.encode('{"error":"unauthorized"}')), 401));
    final c = Web3CSyncClient(
      baseUrl: 'https://x.test',
      instance: 'iptv',
      deviceKey: await DeviceKey.generate(),
      groupId: GroupLink.generateGroupId(),
      groupKey: GroupLink.generateGroupKey(),
      httpClient: mock,
    );
    await expectLater(
        c.stream(0).toList(), throwsA(isA<UnauthorizedException>()));
  });
}
