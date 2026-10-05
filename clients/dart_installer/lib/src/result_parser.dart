import 'dart:convert';

import 'errors.dart';
import 'redactor.dart';

/// Parsed `WEB3C_RESULT` line.
final class ScriptResult {
  const ScriptResult(this.json);
  final Map<String, Object?> json;

  bool get ok => json['ok'] == true;
  String? str(String k) => json[k] is String ? json[k] as String : null;
  bool? flag(String k) => json[k] is bool ? json[k] as bool : null;
}

const resultPrefix = 'WEB3C_RESULT ';

/// Finds the LAST `WEB3C_RESULT {json}` line of [stdout]. Returns null when
/// absent or not valid JSON object.
ScriptResult? parseResult(String stdout) {
  Map<String, Object?>? found;
  for (final line in const LineSplitter().convert(stdout)) {
    if (!line.startsWith(resultPrefix)) continue;
    try {
      final v = jsonDecode(line.substring(resultPrefix.length));
      if (v is Map<String, Object?>) found = v;
    } on FormatException {
      // keep looking: an earlier valid line may exist, but a garbled last one
      // means no trustworthy result.
      found = null;
    }
  }
  return found == null ? null : ScriptResult(found);
}

/// Maps a failed result to its typed error (message sanitized).
InstallerException errorFromResult(ScriptResult r, Redactor red) {
  final code = RegExp(r'^[A-Z_]{1,40}$').hasMatch(r.str('error') ?? '') ? r.str('error')! : 'SCRIPT_ERROR';
  final msg = red.clean(r.str('message') ?? 'the installation script failed', max: 300);
  switch (code) {
    case 'DOCKER_MISSING':
    case 'DOCKER_DAEMON':
      return DockerMissing(msg);
    case 'PORTS_BUSY':
      return PortsBusy(msg);
    case 'HEALTH_FAILED':
      return HealthCheckFailed(msg);
    default:
      return ScriptFailed(code, msg);
  }
}
