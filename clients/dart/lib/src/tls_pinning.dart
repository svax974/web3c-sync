import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import 'crypto.dart';

/// Parses a SHA-256 fingerprint given as hex (optionally colon separated) or
/// base64url.
Uint8List parseFingerprint(String fp) {
  final h = fp.replaceAll(':', '').trim();
  if (RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(h)) {
    return Uint8List.fromList([
      for (var i = 0; i < 64; i += 2)
        int.parse(h.substring(i, i + 2), radix: 16),
    ]);
  }
  final b = unb64(h);
  if (b.length != 32) throw FormatException('not a SHA-256 fingerprint', fp);
  return b;
}

/// HTTP client trusting only the certificate whose DER SHA-256 equals
/// [fingerprint]. System roots are disabled, so the pin replaces CA
/// validation (self-signed personal servers).
http.Client pinnedHttpClient(String fingerprint) {
  final expected = parseFingerprint(fingerprint);
  final ctx = SecurityContext(withTrustedRoots: false);
  final hc = HttpClient(context: ctx)
    ..badCertificateCallback = (cert, host, port) {
      final got = sha256(cert.der);
      var diff = 0;
      for (var i = 0; i < 32; i++) {
        diff |= got[i] ^ expected[i];
      }
      return diff == 0;
    };
  return IOClient(hc);
}
