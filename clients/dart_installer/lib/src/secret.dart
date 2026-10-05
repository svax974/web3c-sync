import 'dart:convert';
import 'dart:typed_data';

/// A secret held as bytes so it can be overwritten once used.
///
/// Limit (Dart): the `String` the caller built the secret from, and the
/// transient `String` that the SSH library needs at the moment of
/// authentication, are immutable and stay in memory until garbage collected;
/// they cannot be zeroed. Only this class' own buffer is wiped.
final class Secret {
  Secret.fromString(String value) : _bytes = Uint8List.fromList(utf8.encode(value));
  Secret.fromBytes(List<int> value) : _bytes = Uint8List.fromList(value);

  Uint8List? _bytes;

  bool get isWiped => _bytes == null;

  /// Decodes the secret (creates a non-wipeable String).
  String reveal() {
    final b = _bytes;
    if (b == null) throw StateError('secret already wiped');
    return utf8.decode(b);
  }

  /// Overwrites the buffer with zeros and drops it.
  void wipe() {
    final b = _bytes;
    if (b != null) b.fillRange(0, b.length, 0);
    _bytes = null;
  }

  @override
  String toString() => 'Secret(***)';
}
