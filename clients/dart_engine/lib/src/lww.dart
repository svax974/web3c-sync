import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

/// JSON with object keys sorted at every level: the same value always gives the
/// same text, on every device. Used for the deterministic tie-break and for
/// change detection.
String canonicalJson(Object? value) => jsonEncode(_sorted(value));

Object? _sorted(Object? v) {
  if (v is Map) {
    final keys = v.keys.map((k) => '$k').toList()..sort();
    return {for (final k in keys) k: _sorted(v[k])};
  }
  if (v is List) return [for (final e in v) _sorted(e)];
  return v;
}

/// Short stable digest of a payload (change detection only, not security).
String payloadHash(Object? payload) => crypto.sha256
    .convert(utf8.encode(canonicalJson(payload)))
    .toString()
    .substring(0, 16);

/// A payload with the instant (epoch ms) it was last modified.
class Versioned {
  const Versioned(this.payload, this.updatedAt);
  final Object? payload;
  final int updatedAt;
}

/// The single merge rule of the whole model: **the most recent `u` wins**; on a
/// tie the larger canonical serialisation wins (`String.compareTo`, UTF-16 code
/// unit order). Deterministic, so every device converges on the same version
/// whatever the order in which it saw the two.
///
/// Returns true when [local] wins.
bool localWins(Versioned local, Versioned remote) {
  if (local.updatedAt != remote.updatedAt) {
    return local.updatedAt > remote.updatedAt;
  }
  return canonicalJson(local.payload).compareTo(canonicalJson(remote.payload)) >
      0;
}
