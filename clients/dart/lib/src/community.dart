import 'dart:convert';

import 'package:http/http.dart' as http;

import 'crypto.dart';
import 'errors.dart';
import 'transport.dart';

class RatingAggregate {
  const RatingAggregate(this.count, this.sum, this.avg);
  factory RatingAggregate.fromJson(Map<String, dynamic> j) => RatingAggregate(
        (j['count'] as num?)?.toInt() ?? 0,
        (j['sum'] as num?)?.toDouble() ?? 0,
        (j['avg'] as num?)?.toDouble() ?? 0,
      );
  final int count;
  final double sum;
  final double avg;
}

/// Public community ratings (spec 9). No device signature on these routes.
///
/// Redirects are never followed; a 3xx is a [ServerException]. `http://` is
/// refused except on loopback ([ArgumentError]).
class CommunityClient {
  CommunityClient(String baseUrl, this.powBits,
      {http.Client? httpClient, DateTime Function()? clock})
      : baseUrl = checkBaseUrl(baseUrl),
        _http = httpClient ?? http.Client(),
        _clock = clock ?? DateTime.now;

  final String baseUrl;
  final int powBits;
  final http.Client _http;
  final DateTime Function() _clock;

  static final _keyRe = RegExp(r'^(movie|tv|series):tmdb:[0-9]{1,9}$');

  void close() => _http.close();

  Future<http.Response> _send(String method, String path,
      {Object? json}) async {
    final req = http.Request(method, Uri.parse('$baseUrl$path'))
      ..followRedirects = false;
    if (json != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(json);
    }
    final res = await http.Response.fromStream(await _http.send(req));
    checkResponse(res);
    return res;
  }

  /// Casts, replaces (new rating) or removes (null) this profile's vote.
  ///
  /// [kRating] is K_rating (`deriveKeys(kg).rating`) for a synced profile,
  /// else a local random key. The body carries `t` (now, epoch seconds), which
  /// is part of the proof of work. The server refuses (409,
  /// [ConflictException]) a vote whose `t` is not strictly later than the
  /// stored one, so two votes of one pseudonym in the same second conflict.
  /// [contentKey] must match `^(movie|tv|series):tmdb:[0-9]{1,9}$`
  /// ([ArgumentError] otherwise).
  Future<void> vote(
    String contentKey,
    String profileId,
    List<int> kRating,
    num? rating,
  ) async {
    _checkKey(contentKey);
    final p = pseudonym(kRating, profileId, contentKey);
    final t = _clock().millisecondsSinceEpoch ~/ 1000;
    final n = await solvePowAsync(contentKey, p, rating, powBits, t: t);
    final r = rating == null
        ? null
        : (rating == rating.truncate() ? rating.toInt() : rating);
    await _send('PUT', '/v1/public/ratings/$contentKey',
        json: {'p': p, 'r': r, 't': t, 'n': n});
  }

  Future<RatingAggregate> get(String contentKey) async {
    _checkKey(contentKey);
    final res = await _send('GET', '/v1/public/ratings/$contentKey');
    return RatingAggregate.fromJson(
        jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>);
  }

  /// Up to 100 keys per call; larger lists are split.
  Future<Map<String, RatingAggregate>> query(List<String> keys) async {
    keys.forEach(_checkKey);
    final out = <String, RatingAggregate>{};
    for (var i = 0; i < keys.length; i += 100) {
      final chunk =
          keys.sublist(i, i + 100 > keys.length ? keys.length : i + 100);
      final res = await _send('POST', '/v1/public/ratings/query',
          json: {'keys': chunk});
      final items = (jsonDecode(utf8.decode(res.bodyBytes)) as Map)['items']
          as Map<String, dynamic>;
      items.forEach((k, v) =>
          out[k] = RatingAggregate.fromJson(v as Map<String, dynamic>));
    }
    return out;
  }

  static void _checkKey(String k) {
    if (!_keyRe.hasMatch(k)) throw ArgumentError.value(k, 'contentKey');
  }
}
