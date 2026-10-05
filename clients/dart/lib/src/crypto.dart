import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

const protocolVersion = 'web3c-sync/v1';
const envelopeVersion = 0x01;
const _nonceLen = 12;
const _tagLen = 16;

final _sha256 = const DartSha256();
final _aes = DartAesGcm.with256bits();
final Random _rng = Random.secure();

/// Thrown when an envelope cannot be opened. Deliberately carries no cause.
class DecryptException implements Exception {
  const DecryptException();
  @override
  String toString() => 'DecryptException';
}

String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List unb64(String s) {
  if (s.contains('=') || s.contains('+') || s.contains('/')) {
    throw FormatException('not base64url without padding', s);
  }
  return Uint8List.fromList(base64Url.decode(base64Url.normalize(s)));
}

Uint8List randomBytes(int n) =>
    Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

Uint8List sha256(List<int> data) =>
    Uint8List.fromList(_sha256.hashSync(data).bytes);

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List hmacSha256(List<int> key, List<int> data) {
  const block = 64;
  var k = key.length > block ? sha256(key) : Uint8List.fromList(key);
  if (k.length < block) {
    k = Uint8List(block)..setRange(0, k.length, k);
  }
  final ipad = Uint8List(block), opad = Uint8List(block);
  for (var i = 0; i < block; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  final inner = sha256([...ipad, ...data]);
  return sha256([...opad, ...inner]);
}

/// HKDF-SHA256 (RFC 5869), single block (length <= 32).
Uint8List hkdf(List<int> ikm, List<int> salt, String info, [int length = 32]) {
  assert(length <= 32);
  final prk = hmacSha256(salt, ikm);
  final okm = hmacSha256(prk, [...utf8.encode(info), 1]);
  return Uint8List.sublistView(okm, 0, length);
}

/// u16(len) || x
Uint8List field(List<int> x) {
  if (x.length > 0xffff) throw ArgumentError('field too long');
  return Uint8List.fromList([x.length >> 8, x.length & 0xff, ...x]);
}

Uint8List fields(List<String> parts) =>
    Uint8List.fromList([for (final p in parts) ...field(utf8.encode(p))]);

class DerivedKeys {
  const DerivedKeys(this.enc, this.id, this.name);
  final Uint8List enc;
  final Uint8List id;
  final Uint8List name;
}

DerivedKeys deriveKeys(List<int> kg) {
  final salt = utf8.encode(protocolVersion);
  return DerivedKeys(
    hkdf(kg, salt, 'enc'),
    hkdf(kg, salt, 'id'),
    hkdf(kg, salt, 'name'),
  );
}

/// Pseudonymised document identifier (spec 4).
String docId(List<int> kId, String collection, String logicalId) =>
    b64(hmacSha256(kId, fields([collection, logicalId])));

int _bitLen(int x) => x == 0 ? 0 : x.bitLength;

int padme(int l) {
  if (l < 2) return l;
  final e = _bitLen(l) - 1;
  final s = _bitLen(e);
  final z = e - s;
  final mask = (1 << z) - 1;
  return (l + mask) & ~mask;
}

Uint8List _pad(List<int> p) {
  final m = Uint8List(padme(p.length + 1));
  m.setRange(0, p.length, p);
  m[p.length] = 0x80;
  return m;
}

Uint8List _unpad(List<int> m) {
  var i = m.length - 1;
  while (i >= 0 && m[i] == 0) {
    i--;
  }
  if (i < 0 || m[i] != 0x80) throw const DecryptException();
  return Uint8List.fromList(m.sublist(0, i));
}

/// Binds a ciphertext to instance, group, collection and document (spec 3).
Uint8List aad(
  String instance,
  String groupId,
  String collection,
  String docId,
) =>
    Uint8List.fromList([
      ...utf8.encode(protocolVersion),
      0,
      ...fields([instance, groupId, collection, docId]),
    ]);

/// Encrypts [plaintext] into an envelope. [nonce] is only for test vectors:
/// reusing a nonce with the same key breaks AES-GCM.
Future<Uint8List> seal(
  List<int> kEnc,
  List<int> aad,
  List<int> plaintext, {
  List<int>? nonce,
}) async {
  nonce ??= randomBytes(_nonceLen);
  if (nonce.length != _nonceLen) throw ArgumentError('nonce must be 12 bytes');
  final box = await _aes.encrypt(
    _pad(plaintext),
    secretKey: SecretKeyData(kEnc),
    nonce: nonce,
    aad: aad,
  );
  return Uint8List.fromList(
    [envelopeVersion, ...nonce, ...box.cipherText, ...box.mac.bytes],
  );
}

Future<Uint8List> open(
  List<int> kEnc,
  List<int> aad,
  List<int> env,
) async {
  if (env.length < 1 + _nonceLen + _tagLen + 1 || env[0] != envelopeVersion) {
    throw const DecryptException();
  }
  try {
    final box = SecretBox(
      env.sublist(1 + _nonceLen, env.length - _tagLen),
      nonce: env.sublist(1, 1 + _nonceLen),
      mac: Mac(env.sublist(env.length - _tagLen)),
    );
    final m = await _aes.decrypt(box, secretKey: SecretKeyData(kEnc), aad: aad);
    return _unpad(m);
  } on DecryptException {
    rethrow;
  } catch (_) {
    throw const DecryptException();
  }
}

String bodyHash(List<int> body) => hex(sha256(body));

/// [pathQuery] must be exactly the request-target sent on the wire.
Uint8List canonicalRequest({
  required String method,
  required String pathQuery,
  required String timestamp,
  required String nonce,
  required String bodyHash,
  required String instance,
}) =>
    Uint8List.fromList(utf8.encode(
      '$protocolVersion\n$method\n$pathQuery\n$timestamp\n$nonce\n$bodyHash\n$instance',
    ));

/// Shortest decimal text of a rating: `7`, `7.5`, `null`. Never `7.0`.
String ratingText(num? r) {
  if (r == null) return 'null';
  final d = r.toDouble();
  if (d.isNaN || d.isInfinite) throw ArgumentError('invalid rating');
  if (d == d.truncateToDouble() && d.abs() < 1e15) {
    return d == 0 ? '0' : d.toInt().toString();
  }
  final s = d.toString();
  return s.contains('e') ? _expandExponent(s) : s;
}

String _expandExponent(String s) {
  final neg = s.startsWith('-');
  final parts = (neg ? s.substring(1) : s).split('e');
  final exp = int.parse(parts[1]);
  final mant = parts[0].split('.');
  final intPart = mant[0];
  final frac = mant.length > 1 ? mant[1] : '';
  var digits = intPart + frac;
  var point = intPart.length + exp;
  String out;
  if (point <= 0) {
    out = '0.${'0' * -point}$digits';
  } else if (point >= digits.length) {
    out = digits + '0' * (point - digits.length);
  } else {
    out = '${digits.substring(0, point)}.${digits.substring(point)}';
  }
  if (out.contains('.')) {
    out = out.replaceFirst(RegExp(r'0+$'), '').replaceFirst(RegExp(r'\.$'), '');
  }
  return neg ? '-$out' : out;
}

String pseudonym(List<int> kUser, String profileId, String contentKey) =>
    b64(hmacSha256(kUser, fields(['rating', profileId, contentKey])));

Uint8List powDigest(String contentKey, String pseudonym, num? r, int n) {
  final u64 = ByteData(8)..setUint64(0, n);
  return sha256([
    ...field(utf8.encode(contentKey)),
    ...field(utf8.encode(pseudonym)),
    ...utf8.encode(ratingText(r)),
    ...u64.buffer.asUint8List(),
  ]);
}

int leadingZeroBits(List<int> h) {
  var n = 0;
  for (final b in h) {
    if (b == 0) {
      n += 8;
      continue;
    }
    return n + (8 - b.bitLength);
  }
  return n;
}

bool powOk(String contentKey, String pseudonym, num? r, int n, int powBits) =>
    leadingZeroBits(powDigest(contentKey, pseudonym, r, n)) >= powBits;

/// Smallest nonce satisfying the proof of work. CPU-bound: prefer
/// [solvePowAsync] on a UI isolate.
int solvePow(String contentKey, String pseudonym, num? r, int powBits) {
  for (var n = 0;; n++) {
    if (powOk(contentKey, pseudonym, r, n, powBits)) return n;
  }
}

/// Same result as [solvePow], yielding to the event loop every [yieldEvery]
/// iterations.
Future<int> solvePowAsync(
  String contentKey,
  String pseudonym,
  num? r,
  int powBits, {
  int yieldEvery = 2000,
}) async {
  for (var n = 0;; n++) {
    if (powOk(contentKey, pseudonym, r, n, powBits)) return n;
    if (n % yieldEvery == yieldEvery - 1) {
      await Future<void>.delayed(Duration.zero);
    }
  }
}
