import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

/// What the UI shows to the user for a first-time confirmation.
final class HostKeyInfo {
  const HostKeyInfo({required this.type, required this.sha256Fingerprint, this.md5});

  /// SSH key type, e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`.
  final String type;

  /// OpenSSH style: `SHA256:<base64 without padding>` (what `ssh-keygen -lf`
  /// prints). Compare it with the server's own console.
  final String sha256Fingerprint;

  /// Legacy MD5 fingerprint, when available (the SSH library only exposes
  /// SHA-256, so this is normally null).
  final String? md5;

  @override
  String toString() => 'HostKeyInfo($type, $sha256Fingerprint)';
}

typedef HostKeyConfirm = Future<bool> Function(HostKeyInfo info);

/// Normalizes `SHA256:xxx`, bare base64 (padded or not) or 64 hex digits to
/// `SHA256:<base64 no padding>`. Returns null when malformed.
String? normalizeSha256Fingerprint(String s) {
  var t = s.trim();
  if (t.toUpperCase().startsWith('SHA256:')) t = t.substring(7);
  try {
    if (RegExp(r'^[0-9a-fA-F:]{64,95}$').hasMatch(t)) {
      final h = t.replaceAll(':', '');
      if (h.length != 64) return null;
      final b = Uint8List.fromList([for (var i = 0; i < 64; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
      return 'SHA256:${base64.encode(b).replaceAll('=', '')}';
    }
    final stripped = t.replaceAll('=', '');
    if (!RegExp(r'^[A-Za-z0-9+/]{43}$').hasMatch(stripped)) return null;
    final b = base64.decode(base64.normalize(stripped));
    if (b.length != 32) return null;
    return 'SHA256:$stripped';
  } on FormatException {
    return null;
  }
}

enum HostKeyDecision { acceptedPinned, acceptedConfirmed, rejected, changed }

/// Trust-on-first-use state machine. Exactly one of:
///  * a fingerprint was pinned in advance: equal -> accept silently,
///    different -> [HostKeyDecision.changed] (hard error, callback NOT asked);
///  * no pin: the mandatory callback decides (true/false).
/// A callback that throws counts as a rejection (fail closed).
final class HostKeyVerifier {
  HostKeyVerifier({required this.onHostKey, String? expectedSha256})
      : expected = expectedSha256 == null ? null : normalizeSha256Fingerprint(expectedSha256) {
    if (expectedSha256 != null && expected == null) {
      throw const InvalidRequest('expectedHostKeySha256', 'not a SHA-256 fingerprint');
    }
  }

  final HostKeyConfirm onHostKey;
  final String? expected;

  HostKeyDecision? decision;
  String? presented;

  Future<bool> verify(String type, Uint8List fingerprintAscii) async {
    final fp = utf8.decode(fingerprintAscii);
    presented = normalizeSha256Fingerprint(fp) ?? fp;
    final pin = expected;
    if (pin != null) {
      if (pin == presented) {
        decision = HostKeyDecision.acceptedPinned;
        return true;
      }
      decision = HostKeyDecision.changed;
      return false;
    }
    bool ok;
    try {
      ok = await onHostKey(HostKeyInfo(type: type, sha256Fingerprint: presented!));
    } catch (_) {
      ok = false;
    }
    decision = ok ? HostKeyDecision.acceptedConfirmed : HostKeyDecision.rejected;
    return ok;
  }

  /// The typed error matching a failed decision, or null when accepted.
  InstallerException? errorFor() => switch (decision) {
        HostKeyDecision.rejected => HostKeyRejected(presented ?? ''),
        HostKeyDecision.changed => HostKeyChanged(expectedSha256: expected!, presentedSha256: presented ?? ''),
        _ => null,
      };
}
