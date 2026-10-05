import 'package:http/http.dart' as http;

/// Validates and normalises a server base URL: https, or http on a loopback
/// host only (127.0.0.1, ::1, localhost). Throws [ArgumentError] otherwise.
String checkBaseUrl(String baseUrl) {
  final trimmed = baseUrl.replaceFirst(RegExp(r'/+$'), '');
  final Uri u;
  try {
    u = Uri.parse(trimmed);
  } on FormatException {
    throw ArgumentError.value(baseUrl, 'baseUrl', 'not a URL');
  }
  final host = u.host.toLowerCase();
  if (host.isEmpty) {
    throw ArgumentError.value(baseUrl, 'baseUrl', 'missing host');
  }
  if (u.scheme == 'https') return trimmed;
  if (u.scheme == 'http' &&
      (host == 'localhost' || host == '127.0.0.1' || host == '::1')) {
    return trimmed;
  }
  throw ArgumentError.value(
      baseUrl, 'baseUrl', 'cleartext http is only allowed on loopback');
}

/// Request that never follows redirects.
http.Request noRedirect(http.Request r) => r..followRedirects = false;
