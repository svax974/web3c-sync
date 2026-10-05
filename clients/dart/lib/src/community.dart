import 'dart:convert';

import 'package:http/http.dart' as http;

import 'crypto.dart';
import 'errors.dart';

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
class CommunityClient {
  CommunityClient(String baseUrl, this.powBits, {http.Client? httpClient})
      : baseUrl = baseUrl.replaceFirst(RegExp(r'/+$'), ''),
        _http = httpClient ?? http.Client();

  final String baseUrl;
  final int powBits;
  final http.Client _http;

  static final _keyRe = RegExp(r'^[a-z0-9:_.-]{1,128}$');

  void close() => _http.close();

  /// Casts, replaces (new rating) or removes (null) this profile's vote.
  /// [kUser] is K_id for a synced profile, else a local random key.
  Future<void> vote(
    String contentKey,
    String profileId,
    List<int> kUser,
    num? rating,
  ) async {
    _checkKey(contentKey);
    final p = pseudonym(kUser, profileId, contentKey);
    final n = await solvePowAsync(contentKey, p, rating, powBits);
    final r = rating == null
        ? null
        : (rating == rating.truncate() ? rating.toInt() : rating);
    final res = await _http.put(
      Uri.parse('$baseUrl/v1/public/ratings/$contentKey'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'p': p, 'r': r, 'n': n}),
    );
    checkResponse(res);
  }

  Future<RatingAggregate> get(String contentKey) async {
    _checkKey(contentKey);
    final res =
        await _http.get(Uri.parse('$baseUrl/v1/public/ratings/$contentKey'));
    checkResponse(res);
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
      final res = await _http.post(
        Uri.parse('$baseUrl/v1/public/ratings/query'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'keys': chunk}),
      );
      checkResponse(res);
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
