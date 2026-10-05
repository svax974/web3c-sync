import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

const _link =
    'web3c-link:v1?s=https%3A%2F%2Fsecret-host.example&i=iptv&g=AAAA&t=TOKEN&k=GROUPKEYSECRET';

void main() {
  group('describeSyncError never leaks', () {
    final leaky = <Object>[
      FormatException('bad link', _link),
      ArgumentError.value('https://secret-host.example/x', 'baseUrl'),
      const SocketException('Failed host lookup: secret-host.example'),
      http.ClientException('failed', Uri.parse('https://secret-host.example')),
      TimeoutException('timeout at secret-host.example'),
      StateError('bad state'),
      Exception('anything https://secret-host.example'),
      const ServerException(502, 'upstream'),
      const BadRequestException('bad_request'),
    ];
    for (final e in leaky) {
      test('${e.runtimeType}', () {
        final s = describeSyncError(e);
        for (final bad in ['secret-host', 'GROUPKEYSECRET', 'TOKEN', 'web3c-link']) {
          expect(s, isNot(contains(bad)));
        }
      });
    }
  });

  test('typed protocol errors get a fixed sentence', () {
    expect(describeSyncError(const RollbackException('x')), contains('rollback'));
    expect(describeSyncError(const UnauthorizedException()),
        contains('access denied'));
    expect(describeSyncError(const ForbiddenException()),
        contains('access denied'));
    expect(describeSyncError(const QuotaException(413, 'too_large')),
        contains('too large'));
    expect(describeSyncError(const QuotaException(429, 'quota', 'tokens')),
        contains('tokens'));
    expect(describeSyncError(const ServerException(503, 'unavailable')),
        contains('HTTP 503'));
    expect(describeSyncError(const SyncEngineException('already safe')), 'already safe');
    expect(describeSyncError(Object()), 'error Object');
  });

  test('SyncEngineException carries the rollback flag and its own text only', () {
    const e = SyncEngineException('boom', rollback: true);
    expect(e.rollback, isTrue);
    expect(e.toString(), contains('boom'));
  });

  test('isRetryableSyncError: network / 5xx / rate limit / conflict only', () {
    expect(isRetryableSyncError(const SocketException('x')), isTrue);
    expect(isRetryableSyncError(TimeoutException('x')), isTrue);
    expect(isRetryableSyncError(const ServerException(500, 'x')), isTrue);
    expect(isRetryableSyncError(const ServerException(404, 'x')), isFalse);
    expect(isRetryableSyncError(const RateLimitedException()), isTrue);
    expect(isRetryableSyncError(const ConflictException(3)), isTrue);
    expect(isRetryableSyncError(const QuotaException(429, 'quota')), isTrue);
    expect(isRetryableSyncError(const QuotaException(413, 'too_large')), isFalse);
    expect(isRetryableSyncError(const UnauthorizedException()), isFalse);
    expect(isRetryableSyncError(const RollbackException('x')), isFalse);
  });

  test('retryAfterOf reads Retry-After from a rate limit only', () {
    expect(
        retryAfterOf(const RateLimitedException(Duration(seconds: 7))),
        const Duration(seconds: 7));
    expect(retryAfterOf(const ServerException(500, 'x')), isNull);
  });

  group('backoffDelay', () {
    const min = Duration(seconds: 2), max = Duration(minutes: 5);
    test('doubles from min and is capped at max', () {
      Duration d(int n) => backoffDelay(n, min: min, max: max);
      expect(d(1), const Duration(seconds: 2));
      expect(d(2), const Duration(seconds: 4));
      expect(d(3), const Duration(seconds: 8));
      expect(d(8), const Duration(seconds: 256));
      expect(d(9), max);
      expect(d(100), max);
      expect(d(0), const Duration(seconds: 2)); // never below one try
    });
    test('Retry-After wins, capped at max; zero is ignored', () {
      expect(backoffDelay(1, min: min, max: max, retryAfter: const Duration(seconds: 30)),
          const Duration(seconds: 30));
      expect(backoffDelay(1, min: min, max: max, retryAfter: const Duration(hours: 1)), max);
      expect(backoffDelay(3, min: min, max: max, retryAfter: Duration.zero),
          const Duration(seconds: 8));
    });
  });
}
