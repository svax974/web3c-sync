/// Removes secrets from any text that leaves the package (progress lines, error
/// messages). Known secrets are replaced literally; additionally any 64-char
/// hex string that is not a `sha256:` digest is masked (admin tokens).
final class Redactor {
  final _known = <String>{};

  void add(String? secret) {
    if (secret != null && secret.length >= 4) _known.add(secret);
  }

  static final _hex64 = RegExp(r'(?<!sha256:)(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])');
  static final _ctl = RegExp(r'[\x00-\x08\x0b-\x1f\x7f]');

  /// Sanitizes one line: control characters removed, secrets masked, length
  /// capped.
  String clean(String s, {int max = 400}) {
    var out = s.replaceAll(_ctl, '');
    // Longest first so that a secret containing another is fully masked.
    final secrets = _known.toList()..sort((a, b) => b.length - a.length);
    for (final k in secrets) {
      out = out.replaceAll(k, '***');
    }
    out = out.replaceAll(_hex64, '***');
    if (out.length > max) out = '${out.substring(0, max)}...';
    return out;
  }
}
