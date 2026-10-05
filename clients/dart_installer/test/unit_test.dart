import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:web3c_sync_installer/web3c_sync_installer.dart';
import 'package:web3c_sync_installer/src/hostkey.dart';
import 'package:web3c_sync_installer/src/redactor.dart';
import 'package:web3c_sync_installer/src/result_parser.dart';

import 'fakes.dart';

void main() {
  group('parseResult', () {
    test('takes the last WEB3C_RESULT line, ignores noise', () {
      final r = parseResult('hello\nWEB3C_RESULT {"ok":false,"error":"X"}\nnoise\nWEB3C_RESULT {"ok":true,"url":"https://a"}\n')!;
      expect(r.ok, isTrue);
      expect(r.str('url'), 'https://a');
    });
    test('absent / garbled / not an object -> null', () {
      expect(parseResult('nothing'), isNull);
      expect(parseResult('WEB3C_RESULT {oops'), isNull);
      expect(parseResult('WEB3C_RESULT [1]'), isNull);
      expect(parseResult('WEB3C_RESULT {"ok":true}\nWEB3C_RESULT {garbled'), isNull);
    });
    test('does not match a prefix inside a line', () {
      expect(parseResult('x WEB3C_RESULT {"ok":true}'), isNull);
    });
    test('error mapping', () {
      final red = Redactor();
      InstallerException e(String code) => errorFromResult(ScriptResult({'ok': false, 'error': code, 'message': 'm'}), red);
      expect(e('PORTS_BUSY'), isA<PortsBusy>());
      expect(e('DOCKER_MISSING'), isA<DockerMissing>());
      expect(e('HEALTH_FAILED'), isA<HealthCheckFailed>());
      final other = e('PULL_FAILED') as ScriptFailed;
      expect(other.code, 'PULL_FAILED');
      expect((e('lowercase injected') as ScriptFailed).code, 'SCRIPT_ERROR');
    });
  });

  group('Redactor', () {
    test('masks known secrets, bare 64-hex tokens, keeps sha256 digests', () {
      final r = Redactor()..add('hunter2-secret');
      final tok = 'a1' * 32;
      final dg = 'sha256:${'b2' * 32}';
      final out = r.clean('pw hunter2-secret tok $tok digest $dg ctl\x07x');
      expect(out, isNot(contains('hunter2-secret')));
      expect(out, isNot(contains(tok)));
      expect(out, contains(dg));
      expect(out, isNot(contains('\x07')));
    });
    test('caps length', () => expect(Redactor().clean('x' * 1000).length, lessThan(500)));
  });

  group('normalizeSha256Fingerprint', () {
    final raw = Uint8List.fromList(List.generate(32, (i) => i));
    final b64 = base64.encode(raw).replaceAll('=', '');
    final hex = raw.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    test('accepts SHA256:b64, b64, padded b64, hex, colon hex', () {
      final want = 'SHA256:$b64';
      expect(normalizeSha256Fingerprint('SHA256:$b64'), want);
      expect(normalizeSha256Fingerprint(b64), want);
      expect(normalizeSha256Fingerprint('$b64='), want);
      expect(normalizeSha256Fingerprint(hex), want);
      expect(normalizeSha256Fingerprint([for (var i = 0; i < 64; i += 2) hex.substring(i, i + 2)].join(':')), want);
    });
    test('rejects junk', () {
      expect(normalizeSha256Fingerprint('SHA256:short'), isNull);
      expect(normalizeSha256Fingerprint(''), isNull);
      expect(normalizeSha256Fingerprint('x' * 43), isNull);
    });
  });

  group('HostKeyVerifier (TOFU)', () {
    Uint8List ascii(String s) => Uint8List.fromList(utf8.encode(s));
    test('first connection: callback decides; accept', () async {
      HostKeyInfo? seen;
      final v = HostKeyVerifier(onHostKey: (i) async {
        seen = i;
        return true;
      });
      expect(await v.verify('ssh-ed25519', ascii(fpOf(1))), isTrue);
      expect(seen!.sha256Fingerprint, fpOf(1));
      expect(seen!.type, 'ssh-ed25519');
      expect(v.decision, HostKeyDecision.acceptedConfirmed);
      expect(v.errorFor(), isNull);
    });
    test('first connection: refusal -> HostKeyRejected', () async {
      final v = HostKeyVerifier(onHostKey: (_) async => false);
      expect(await v.verify('ssh-ed25519', ascii(fpOf(1))), isFalse);
      expect(v.errorFor(), isA<HostKeyRejected>());
    });
    test('a throwing callback fails closed', () async {
      final v = HostKeyVerifier(onHostKey: (_) async => throw StateError('ui crashed'));
      expect(await v.verify('ssh-ed25519', ascii(fpOf(1))), isFalse);
      expect(v.errorFor(), isA<HostKeyRejected>());
    });
    test('pinned and equal: accepted without asking', () async {
      var asked = false;
      final v = HostKeyVerifier(onHostKey: (_) async => asked = true, expectedSha256: fpOf(7));
      expect(await v.verify('ssh-ed25519', ascii(fpOf(7))), isTrue);
      expect(asked, isFalse);
      expect(v.decision, HostKeyDecision.acceptedPinned);
    });
    test('pinned and different: hard HostKeyChanged, callback NOT asked', () async {
      var asked = false;
      final v = HostKeyVerifier(onHostKey: (_) async => asked = true, expectedSha256: fpOf(7));
      expect(await v.verify('ssh-ed25519', ascii(fpOf(8))), isFalse);
      expect(asked, isFalse);
      final e = v.errorFor() as HostKeyChanged;
      expect(e.expectedSha256, fpOf(7));
      expect(e.presentedSha256, fpOf(8));
    });
    test('malformed pin is a request error', () {
      expect(() => HostKeyVerifier(onHostKey: (_) async => true, expectedSha256: 'nope'), throwsA(isA<InvalidRequest>()));
    });
  });

  group('InstallRequest validation (errors never echo the input)', () {
    void bad(String field, InstallRequest Function() f, {String input = 'EVIL-INPUT; rm -rf /'}) {
      try {
        f();
        fail('expected InvalidRequest');
      } on InvalidRequest catch (e) {
        expect(e.field, field);
        expect(e.toString(), isNot(contains(input)));
      }
    }

    test('host / user / port / image / tls', () {
      bad('host', () => InstallRequest(host: 'a b;id', username: 'u', auth: PasswordAuth('p'), instance: SyncInstance.iptv), input: 'a b;id');
      bad('username', () => InstallRequest(host: 'h.example', username: 'u;id', auth: PasswordAuth('p'), instance: SyncInstance.iptv), input: 'u;id');
      bad('port', () => InstallRequest(host: 'h.example', port: 0, username: 'u', auth: PasswordAuth('p'), instance: SyncInstance.iptv), input: '70000');
      bad('image', () => InstallRequest(host: 'h.example', username: 'u', auth: PasswordAuth('p'), instance: SyncInstance.iptv, image: 'x y;id'), input: 'x y;id');
      bad('tls.domain', () => InstallRequest(host: 'h.example', username: 'u', auth: PasswordAuth('p'), instance: SyncInstance.iptv, tls: const TlsMode.domain('bad domain;id')), input: 'bad domain;id');
      bad('tls.hosts', () => InstallRequest(host: 'h.example', username: 'u', auth: PasswordAuth('p'), instance: SyncInstance.iptv, tls: const TlsMode.selfSigned(['1.2.3.4;id'])), input: '1.2.3.4;id');
    });
    test('sudo password required with a key', () {
      bad('sudoPassword', () => InstallRequest(host: 'h.example', username: 'u', auth: PrivateKeyAuth('pem'), instance: SyncInstance.iptv));
    });
    test('toString hides credentials', () {
      expect(req().toString(), isNot(contains('SENTINEL')));
    });
  });

  group('Secret', () {
    test('wipe zeroes the buffer and refuses reuse', () {
      final s = Secret.fromString('abc');
      expect(s.reveal(), 'abc');
      s.wipe();
      expect(s.isWiped, isTrue);
      expect(s.reveal, throwsStateError);
      expect(s.toString(), isNot(contains('abc')));
    });
  });

  group('Web3CInstaller (fake SSH)', () {
    final fp = fpOf(3);

    test('install: parsed result, host key reported, token only in the result', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => okResult(installOk));
      final res = await Web3CInstaller(connector: srv.connector).install(req(), onHostKey: (_) async => true);
      expect(res.url, 'https://203.0.113.7');
      expect(res.adminToken, 'TOKEN');
      expect(res.hostKeySha256, fp);
      expect(res.imageDigest, 'sha256:abc');
      expect(res.toString(), isNot(contains('TOKEN')));
      final cfg = res.toServerConfig();
      expect(cfg.serverUrl, res.url);
      expect(cfg.adminToken, 'TOKEN');
      expect(cfg.tlsFingerprint, res.tlsFingerprint);
      expect(cfg.toString(), isNot(contains('TOKEN')));
    });

    test('uploads script+templates, runs with expected args, cleans the temp dir', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => okResult(installOk));
      await Web3CInstaller(connector: srv.connector).install(
          req(version: '1.2.3', tls: const TlsMode.domain('sync.example.org', email: 'a@b.org')),
          onHostKey: (_) async => true);
      final uploads = srv.calls.where((c) => c.command.startsWith('umask 077; cat >')).toList();
      expect(uploads.map((c) => c.command.split('/').last.replaceAll("'", '')),
          unorderedEquals(['install.sh', 'docker-compose.yml.tpl', 'Caddyfile.tpl']));
      final run = srv.calls.firstWhere((c) => c.command.contains('install.sh') && !c.command.startsWith('umask'));
      expect(run.command, contains("'--install'"));
      expect(run.command, contains("'domain=sync.example.org'"));
      expect(run.command, contains("'ghcr.io/svax974/web3c-sync:1.2.3'"));
      expect(srv.calls.last.command, startsWith('rm -rf -- '));
      expect(srv.conn!.closed, isTrue);
    });

    test('rejected host key: nothing runs, no upload, no temp dir', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => fail('must not run'));
      await expectLater(Web3CInstaller(connector: srv.connector).install(req(), onHostKey: (_) async => false),
          throwsA(isA<HostKeyRejected>()));
      expect(srv.calls, isEmpty);
    });

    test('changed host key is a hard error and the UI is not consulted', () async {
      var asked = false;
      final srv = FakeServer(hostFp: fpOf(9), handler: (c, i, e) => fail('must not run'));
      await expectLater(
          Web3CInstaller(connector: srv.connector).install(req(expected: fp), onHostKey: (_) async => asked = true),
          throwsA(isA<HostKeyChanged>()));
      expect(asked, isFalse);
      expect(srv.calls, isEmpty);
    });

    test('pinned host key + same key: no prompt', () async {
      var asked = false;
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => okResult(installOk));
      await Web3CInstaller(connector: srv.connector).install(req(expected: fp), onHostKey: (_) async => asked = true);
      expect(asked, isFalse);
    });

    test('auth failure', () async {
      final srv = FakeServer(hostFp: fp, authFails: true, handler: (c, i, e) => fail('x'));
      await expectLater(Web3CInstaller(connector: srv.connector).install(req(), onHostKey: (_) async => true), throwsA(isA<AuthFailed>()));
    });

    test('script errors map to typed exceptions', () async {
      Future<Object> run(String code) async {
        final srv = FakeServer(hostFp: fp, handler: (c, i, e) => okResult('{"ok":false,"error":"$code","message":"msg"}'));
        try {
          await Web3CInstaller(connector: srv.connector).install(req(), onHostKey: (_) async => true);
        } catch (e) {
          return e;
        }
        fail('no error');
      }

      expect(await run('DOCKER_MISSING'), isA<DockerMissing>());
      expect(await run('PORTS_BUSY'), isA<PortsBusy>());
      expect(await run('HEALTH_FAILED'), isA<HealthCheckFailed>());
      final f = await run('PULL_FAILED') as ScriptFailed;
      expect(f.code, 'PULL_FAILED');
    });

    test('no result line -> ScriptFailed NO_RESULT', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => const ExecResult(exitCode: 1, stdout: '', stderrTail: 'boom'));
      final e = await Web3CInstaller(connector: srv.connector).install(req(), onHostKey: (_) async => true).then<Object>((_) => 'ok', onError: (Object e) => e);
      expect((e as ScriptFailed).code, 'NO_RESULT');
    });

    test('install without TLS is refused before connecting', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) => fail('x'));
      await expectLater(Web3CInstaller(connector: srv.connector).install(req(tls: null), onHostKey: (_) async => true), throwsA(isA<InvalidRequest>()));
      expect(srv.connects, 0);
    });

    test('status / upgrade / uninstall', () async {
      final srv = FakeServer(hostFp: fp, handler: (c, i, e) {
        if (c.contains("'--status'")) return okResult('{"ok":true,"action":"status","url":"https://h","instance":"iptv","adminToken":null,"tlsFingerprint":null,"imageDigest":"sha256:d","version":"1","running":true,"healthy":true}');
        if (c.contains("'--upgrade'")) return okResult(installOk.replaceAll('"adminToken":"TOKEN"', '"adminToken":null'));
        return okResult('{"ok":true,"action":"uninstall","message":"done"}');
      });
      final inst = Web3CInstaller(connector: srv.connector);
      final st = await inst.status(req(tls: null), onHostKey: (_) async => true);
      expect(st.healthy, isTrue);
      final up = await inst.upgrade(req(image: 'ghcr.io/x/y:2'), onHostKey: (_) async => true);
      expect(up.adminToken, isNull);
      expect(srv.calls.any((c) => c.command.contains("'ghcr.io/x/y:2'")), isTrue);
      final un = await inst.uninstall(req(tls: null, purge: true), onHostKey: (_) async => true);
      expect(un.message, 'done');
      expect(srv.calls.any((c) => c.command.contains("'--purge-data'")), isTrue);
    });
  });

  group('secrets hygiene', () {
    const sshPw = 'ssh-pass-SENTINEL';
    const sudoPw = 'sudo-pass-SENTINEL';
    final token = 'cafe' * 16; // 64 hex chars: looks like an admin token

    test('sudo -S: password on stdin only, never in a command; wiped after; no reuse', () async {
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) => okResult(installOk));
      final r = req(sudo: SudoMode.password, sudoPassword: sudoPw);
      await Web3CInstaller(connector: srv.connector).install(r, onHostKey: (_) async => true);
      for (final c in srv.calls) {
        expect(c.command, isNot(contains(sudoPw)));
        expect(c.command, isNot(contains(sshPw)));
      }
      final run = srv.calls.firstWhere((c) => c.command.startsWith('sudo -S -p'));
      expect(run.command, contains("-k -- env sh '/tmp/w3c-install.ABCDEF/install.sh'"));
      expect(utf8.decode(run.stdin!), '$sudoPw\n');
      expect(r.sudoSecret!.isWiped, isTrue);
      expect(() => r.markUsed(), throwsStateError);
      await expectLater(Web3CInstaller(connector: srv.connector).install(r, onHostKey: (_) async => true), throwsStateError);
    });

    test('sudo falls back to the SSH password; NOPASSWD uses sudo -n', () async {
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) => okResult(installOk));
      await Web3CInstaller(connector: srv.connector).install(req(sudo: SudoMode.password), onHostKey: (_) async => true);
      expect(utf8.decode(srv.calls.firstWhere((c) => c.command.startsWith('sudo -S')).stdin!), '$sshPw\n');
      final srv2 = FakeServer(hostFp: fpOf(3), handler: (c, i, e) => okResult(installOk));
      await Web3CInstaller(connector: srv2.connector).install(req(sudo: SudoMode.nopasswd), onHostKey: (_) async => true);
      final run = srv2.calls.firstWhere((c) => c.command.startsWith('sudo -n'));
      expect(run.stdin, isNull);
    });

    test('wrong sudo password is a SudoFailed that does not echo the password', () async {
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) {
        e?.call('[sudo] password for alice: $sudoPw');
        return const ExecResult(exitCode: 1, stdout: '', stderrTail: 'sudo: 3 incorrect password attempts\n');
      });
      final e = await Web3CInstaller(connector: srv.connector)
          .install(req(sudo: SudoMode.password, sudoPassword: sudoPw), onHostKey: (_) async => true)
          .then<Object>((_) => 'ok', onError: (Object e) => e);
      expect(e, isA<SudoFailed>());
      expect('$e', isNot(contains(sudoPw)));
    });

    test('sudo requiring a password in NOPASSWD mode', () async {
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) => const ExecResult(exitCode: 1, stdout: '', stderrTail: 'sudo: a password is required'));
      await expectLater(Web3CInstaller(connector: srv.connector).install(req(sudo: SudoMode.nopasswd), onHostKey: (_) async => true), throwsA(isA<SudoFailed>()));
    });

    test('progress and errors are sanitized (sentinels everywhere)', () async {
      final events = <String>[];
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) {
        e?.call('log with $sshPw and $sudoPw and $token');
        e?.call('digest sha256:${'c3' * 32} stays');
        return okResult('{"ok":false,"error":"PULL_FAILED","message":"failed with $sshPw $sudoPw $token"}');
      });
      Object? err;
      try {
        await Web3CInstaller(connector: srv.connector).install(
          req(sudo: SudoMode.password, sudoPassword: sudoPw),
          onHostKey: (_) async => true,
          onProgress: (p) => events.add(p.toString()),
        );
      } catch (e) {
        err = e;
      }
      final all = [...events, '$err'].join('\n');
      expect(all, isNot(contains(token))); // unknown 64-hex tokens are masked
      expect(all, isNot(contains(sshPw)));
      expect(all, isNot(contains(sudoPw)));
      expect(all, contains('sha256:${'c3' * 32}'));
      expect(err, isA<ScriptFailed>());
    });

    test('a successful result token never reaches progress', () async {
      final tok = 'ab' * 32;
      final events = <String>[];
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) {
        e?.call('oops leaked $tok');
        return okResult(installOk.replaceAll('TOKEN', tok));
      });
      final res = await Web3CInstaller(connector: srv.connector)
          .install(req(), onHostKey: (_) async => true, onProgress: (p) => events.add(p.toString()));
      expect(res.adminToken, tok);
      expect(events.join('\n'), isNot(contains(tok)));
    });

    test('credentials are wiped even when the call fails', () async {
      final srv = FakeServer(hostFp: fpOf(3), handler: (c, i, e) => fail('x'));
      final r = req();
      await Web3CInstaller(connector: srv.connector).install(r, onHostKey: (_) async => false).then<void>((_) {}, onError: (Object _) {});
      expect((r.auth as PasswordAuth).secret.isWiped, isTrue);
    });
  });
}
