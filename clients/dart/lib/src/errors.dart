import 'dart:convert';

import 'package:http/http.dart' as http;

/// Base class of every error mapped from an HTTP response.
class SyncException implements Exception {
  const SyncException(this.status, this.code, [this.message]);
  final int status;
  final String code;
  final String? message;
  @override
  String toString() =>
      '$runtimeType($status $code${message == null ? '' : ': $message'})';
}

class BadRequestException extends SyncException {
  const BadRequestException([String code = 'bad_request']) : super(400, code);
}

class UnauthorizedException extends SyncException {
  const UnauthorizedException() : super(401, 'unauthorized');
}

class ForbiddenException extends SyncException {
  const ForbiddenException() : super(403, 'forbidden');
}

class NotFoundException extends SyncException {
  const NotFoundException() : super(404, 'not_found');
}

/// 409: [currentSeq] is the document's current seq on the server.
class ConflictException extends SyncException {
  const ConflictException(this.currentSeq) : super(409, 'conflict');
  final int currentSeq;
}

/// 410: the document is a tombstone; [seq] must be used as If-Match to
/// re-create it.
class GoneException extends SyncException {
  const GoneException(this.seq) : super(410, 'gone');
  final int seq;
}

/// 413 (too_large) or 429 (quota).
class QuotaException extends SyncException {
  const QuotaException(super.status, super.code, [this.limit]);
  final String? limit;
}

class RateLimitedException extends SyncException {
  const RateLimitedException([this.retryAfter]) : super(429, 'rate_limited');
  final Duration? retryAfter;
}

class ServerException extends SyncException {
  const ServerException(super.status, super.code);
}

/// A received document does not match its pseudonymised identifier.
class IntegrityException implements Exception {
  const IntegrityException();
  @override
  String toString() => 'IntegrityException';
}

Map<String, dynamic> _errBody(http.BaseResponse r, List<int>? body) {
  if (body == null || body.isEmpty) return const {};
  try {
    final j = jsonDecode(utf8.decode(body));
    return j is Map<String, dynamic> ? j : const {};
  } catch (_) {
    return const {};
  }
}

/// Throws the typed exception for a non-2xx response; returns otherwise.
void checkResponse(http.Response r) {
  if (r.statusCode >= 200 && r.statusCode < 300) return;
  final b = _errBody(r, r.bodyBytes);
  final code = (b['error'] as String?) ?? 'error';
  switch (r.statusCode) {
    case 400:
      throw BadRequestException(code);
    case 401:
      throw const UnauthorizedException();
    case 403:
      throw const ForbiddenException();
    case 404:
      throw const NotFoundException();
    case 409:
      throw ConflictException((b['seq'] as num?)?.toInt() ?? -1);
    case 410:
      throw GoneException(int.tryParse(r.headers['x-seq'] ?? '') ?? -1);
    case 413:
      throw QuotaException(413, code, b['limit'] as String?);
    case 429:
      if (code == 'quota') {
        throw QuotaException(429, code, b['limit'] as String?);
      }
      final s = int.tryParse(r.headers['retry-after'] ?? '');
      throw RateLimitedException(s == null ? null : Duration(seconds: s));
    default:
      throw ServerException(r.statusCode, code);
  }
}
