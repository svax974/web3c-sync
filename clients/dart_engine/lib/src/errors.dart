import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:web3c_sync/web3c_sync.dart';

/// An error whose [message] is safe to show and to log: it never contains a
/// server URL, a token, a key, a pairing link or any document content.
class SyncEngineException implements Exception {
  const SyncEngineException(this.message, {this.rollback = false});
  final String message;

  /// True when the server went backwards (PROTOCOL 3, anti-rollback).
  final bool rollback;

  @override
  String toString() => 'SyncEngineException: $message';
}

/// Turns any error into a short sentence that cannot leak a secret.
///
/// The raw exceptions are NOT safe: `FormatException.toString()` prints the
/// source text (a pairing link carries the group key), `ArgumentError.value`
/// prints the offending value (a server URL), and `SocketException` prints the
/// host. Only the cases listed here are described; anything unknown is
/// reduced to its type name.
String describeSyncError(Object e) {
  if (e is SyncEngineException) return e.message;
  if (e is RollbackException) {
    return 'rollback: the server went back in time '
        '(older document or cursor than already seen)';
  }
  if (e is UnauthorizedException || e is ForbiddenException) {
    return 'access denied: device revoked, group deleted or server '
        'credentials refused';
  }
  if (e is NotFoundException) return 'not found on the server';
  if (e is ConflictException) return 'write conflict (retry needed)';
  if (e is GoneException) return 'document deleted on the server';
  if (e is QuotaException) {
    return e.status == 413
        ? 'document too large for the server'
        : 'server quota reached (${e.limit ?? 'group'})';
  }
  if (e is RateLimitedException) return 'server rate limit reached';
  if (e is BadRequestException) return 'request refused by the server (${e.code})';
  if (e is ServerException) return 'server error (HTTP ${e.status})';
  if (e is IntegrityException ||
      e is DecryptException ||
      e is InvalidDocumentException) {
    return 'unreadable or invalid document';
  }
  if (e is TimeoutException ||
      e is SocketException ||
      e is HandshakeException ||
      e is TlsException ||
      e is http.ClientException) {
    return 'server unreachable';
  }
  if (e is FormatException) return 'invalid format: ${e.message}';
  if (e is ArgumentError) return 'invalid parameter: ${e.message}';
  if (e is StateError) return 'invalid state: ${e.message}';
  return 'error ${e.runtimeType}';
}

/// True for failures worth retrying later (network, 5xx, rate limit).
bool isRetryableSyncError(Object e) =>
    e is TimeoutException ||
    e is SocketException ||
    e is HandshakeException ||
    e is TlsException ||
    e is http.ClientException ||
    e is RateLimitedException ||
    e is ConflictException ||
    (e is ServerException && e.status >= 500) ||
    (e is QuotaException && e.status == 429);

/// A delay the server asked for (`Retry-After`), if [e] carries one.
Duration? retryAfterOf(Object e) =>
    e is RateLimitedException ? e.retryAfter : null;

/// Exponential retry delay: [min] * 2^(tries - 1), capped at [max]. A server
/// `Retry-After` ([retryAfter], when positive) replaces it, capped at [max]
/// too. [tries] counts the failures so far (1 for the first retry).
Duration backoffDelay(
  int tries, {
  required Duration min,
  required Duration max,
  Duration? retryAfter,
}) {
  if (retryAfter != null && retryAfter > Duration.zero) {
    return retryAfter > max ? max : retryAfter;
  }
  final ms = min.inMilliseconds * (1 << (tries.clamp(1, 20) - 1));
  return Duration(milliseconds: ms.clamp(0, max.inMilliseconds));
}
