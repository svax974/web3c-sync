import 'dart:io';

import 'package:test/test.dart';
import 'package:web3c_sync_installer/web3c_sync_installer.dart';

void main() {
  test('embedded script and templates are identical to deploy/install/', () {
    final b = ScriptBundle.embedded();
    for (final name in ['install.sh', 'docker-compose.yml.tpl', 'Caddyfile.tpl']) {
      final disk = File('../../deploy/install/$name').readAsBytesSync();
      expect(b.files[name], equals(disk), reason: '$name drifted: run `dart run tool/gen_bundle.dart`');
    }
  });
}
