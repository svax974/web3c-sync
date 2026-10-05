import 'dart:convert';

import 'script_bundle.g.dart';

/// The files shipped to the host: the install script and its templates, as
/// generated from `deploy/install/` (a test checks they never drift).
final class ScriptBundle {
  const ScriptBundle(this.files);

  /// file name -> content
  final Map<String, List<int>> files;

  static ScriptBundle embedded() => ScriptBundle({
        'install.sh': base64.decode(installShB64),
        'docker-compose.yml.tpl': base64.decode(composeTplB64),
        'Caddyfile.tpl': base64.decode(caddyfileTplB64),
      });
}
