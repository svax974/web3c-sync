import 'crypto.dart';

/// Pairing link: `web3c-link:v1?s=&i=&g=&t=&k=[&f=]`.
class GroupLink {
  const GroupLink({
    required this.server,
    required this.instance,
    required this.groupId,
    required this.token,
    required this.groupKey,
    this.tlsFingerprint,
  });

  final String server;
  final String instance;
  final String groupId;
  final String token;
  final List<int> groupKey;
  final String? tlsFingerprint;

  static const _prefix = 'web3c-link:v1?';

  /// 16 random bytes, base64url.
  static String generateGroupId() => b64(randomBytes(16));

  /// 32 random bytes.
  static List<int> generateGroupKey() => randomBytes(32);

  /// Parses a pairing link. The link carries the group key, so errors are
  /// rebuilt from their message alone: a decoder's `FormatException` would
  /// otherwise echo the offending input (and with it the key) in `toString()`.
  factory GroupLink.parse(String link) {
    try {
      return GroupLink._parse(link);
    } on FormatException catch (e) {
      throw FormatException(e.message);
    } catch (_) {
      throw const FormatException('invalid pairing link');
    }
  }

  factory GroupLink._parse(String link) {
    if (!link.startsWith(_prefix)) {
      throw FormatException('not a web3c-link:v1');
    }
    final q = Uri.splitQueryString(link.substring(_prefix.length));
    String need(String k) {
      final v = q[k];
      if (v == null || v.isEmpty) throw FormatException('missing "$k"');
      return v;
    }

    final k = unb64(need('k'));
    if (k.length != 32) throw FormatException('K_g must be 32 bytes');
    if (unb64(need('g')).length != 16) {
      throw FormatException('groupId must be 16 bytes');
    }
    return GroupLink(
      server: need('s'),
      instance: need('i'),
      groupId: need('g'),
      token: need('t'),
      groupKey: k,
      tlsFingerprint: q['f'],
    );
  }

  String format() {
    String e(String v) => Uri.encodeQueryComponent(v);
    final f = tlsFingerprint;
    return '$_prefix'
        's=${e(server)}&i=${e(instance)}&g=${e(groupId)}&t=${e(token)}'
        '&k=${e(b64(groupKey))}${f == null ? '' : '&f=${e(f)}'}';
  }
}
