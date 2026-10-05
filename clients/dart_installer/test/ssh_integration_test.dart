@TestOn('mac-os || linux')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as c;
import 'package:test/test.dart';
import 'package:web3c_sync_installer/web3c_sync_installer.dart';

/// REAL SSH: an unprivileged OpenSSH `sshd` on 127.0.0.1 (public-key auth to the
/// current user), the installer's dartssh2 client, the EMBEDDED install.sh, and
/// the fake docker/curl/ss shims of deploy/install/test (real openssl). No
/// Docker, no network, nothing outside a temp directory. Skipped cleanly when
/// sshd cannot run unprivileged here.
void main() {
  late Directory tmp;
  late Process sshd;
  late int port;
  late String hostFp; // SHA256:... per ssh-keygen
  late String user;
  late String keyPem;
  late String keyEncPem;
  const keyPass = 'pass-SENTINEL-phrase';
  String? skip;

  Future<ProcessResult> sh(String exe, List<String> a) => Process.run(exe, a);

  setUpAll(() async {
    user = Platform.environment['USER'] ?? '';
    if (!File('/usr/sbin/sshd').existsSync() || !File('/usr/bin/ssh-keygen').existsSync() || user.isEmpty) {
      skip = 'sshd/ssh-keygen/USER unavailable';
      return;
    }
    tmp = Directory.systemTemp.createTempSync('w3c-inst-it.');
    final t = tmp.path;
    for (final k in ['host_key', 'client_key']) {
      await sh('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', '$t/$k']);
    }
    await sh('ssh-keygen', ['-q', '-t', 'ed25519', '-N', keyPass, '-f', '$t/client_key_enc']);
    await sh('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', '$t/stranger_key']);
    File('$t/authorized_keys').writeAsStringSync(
        File('$t/client_key.pub').readAsStringSync() + File('$t/client_key_enc.pub').readAsStringSync());
    await sh('chmod', ['600', '$t/authorized_keys']);
    keyPem = File('$t/client_key').readAsStringSync();
    keyEncPem = File('$t/client_key_enc').readAsStringSync();
    final lf = await sh('ssh-keygen', ['-lf', '$t/host_key.pub', '-E', 'sha256']);
    hostFp = RegExp(r'SHA256:\S+').firstMatch(lf.stdout as String)!.group(0)!;

    final probe = await ServerSocket.bind('127.0.0.1', 0);
    port = probe.port;
    await probe.close();
    File('$t/sshd_config').writeAsStringSync('''
Port $port
ListenAddress 127.0.0.1
HostKey $t/host_key
PidFile $t/sshd.pid
AuthorizedKeysFile $t/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
LogLevel ERROR
''');
    sshd = await Process.start('/usr/sbin/sshd', ['-D', '-e', '-f', '$t/sshd_config']);
    final log = StringBuffer();
    sshd.stderr.transform(utf8.decoder).listen(log.write);
    sshd.stdout.drain<void>();
    var up = false;
    for (var i = 0; i < 50 && !up; i++) {
      try {
        (await Socket.connect('127.0.0.1', port, timeout: const Duration(milliseconds: 200))).destroy();
        up = true;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    if (!up) {
      sshd.kill();
      skip = 'unprivileged sshd could not start here: ${log.toString().trim()}';
      return;
    }
    // Shims on the REMOTE PATH: fake docker/curl/ss/getent + the real openssl.
    Directory('$t/bin').createSync();
    for (final s in ['docker', 'curl', 'ss', 'getent']) {
      File('../../deploy/install/test/shims/$s').copySync('$t/bin/$s');
      await sh('chmod', ['755', '$t/bin/$s']);
    }
    final w = await sh('/bin/sh', ['-c', 'command -v openssl']);
    Link('$t/bin/openssl').createSync((w.stdout as String).trim());
  });

  tearDownAll(() {
    if (skip == null) {
      sshd.kill();
      tmp.deleteSync(recursive: true);
    }
  });

  // One isolated "host" (root prefix, shim state, remote temp parent) per test.
  late Directory root, state, rtmp;
  late int n;
  n = 0;
  setUp(() {
    if (skip != null) return;
    n++;
    root = Directory('${tmp.path}/root$n')..createSync();
    state = Directory('${tmp.path}/state$n')..createSync();
    rtmp = Directory('${tmp.path}/rtmp$n')..createSync();
  });

  void itest(String name, Future<void> Function() body) => test(name, () async {
        if (skip != null) {
          markTestSkipped(skip!);
          return;
        }
        await body();
      });

  InstallRequest request({
    SshAuth? auth,
    String? expected,
    TlsMode? tls = const TlsMode.selfSigned(['203.0.113.7']),
    SyncInstance instance = SyncInstance.iptv,
  }) =>
      InstallRequest(
        host: '127.0.0.1',
        port: port,
        username: user,
        auth: auth ?? PrivateKeyAuth(keyPem),
        sudo: SudoMode.none,
        instance: instance,
        tls: tls,
        expectedHostKeySha256: expected,
        remoteTempParent: rtmp.path,
        remoteEnvironment: {
          'PATH': '${tmp.path}/bin:/usr/bin:/bin:/usr/sbin:/sbin',
          'W3C_ROOT': root.path,
          'SHIM_STATE': state.path,
          'W3C_HEALTH_RETRIES': '2',
          'W3C_HEALTH_DELAY': '0',
        },
      );

  String installDir() => '${root.path}/opt/web3c-sync/iptv';
  List<FileSystemEntity> tempLeft() => rtmp.listSync();
  String allText(Directory d) {
    final b = StringBuffer();
    for (final f in d.listSync(recursive: true).whereType<File>()) {
      try {
        b.writeln(f.readAsStringSync());
      } catch (_) {}
    }
    return b.toString();
  }

  itest('install over real SSH: host key shown, result parsed, secrets contained, temp dir removed', () async {
    HostKeyInfo? shown;
    final events = <String>[];
    final res = await Web3CInstaller().install(
      request(),
      onHostKey: (i) async {
        shown = i;
        return true;
      },
      onProgress: (p) => events.add(p.toString()),
    );
    expect(shown!.sha256Fingerprint, hostFp, reason: 'fingerprint presented to the UI == ssh-keygen -lf');
    expect(shown!.type, contains('ed25519'));
    expect(res.hostKeySha256, hostFp);
    expect(res.url, 'https://203.0.113.7');
    expect(res.adminToken, matches(RegExp(r'^[0-9a-f]{64}$')));
    expect(res.imageDigest, startsWith('sha256:'));
    expect(res.version, '1.2.3');

    // Certificate fingerprint recomputed independently from the file on disk.
    final der = await Process.run('openssl', ['x509', '-in', '${installDir()}/certs/cert.pem', '-outform', 'DER'],
        stdoutEncoding: null);
    final want = base64Url.encode(c.sha256.convert(der.stdout as List<int>).bytes).replaceAll('=', '');
    expect(res.tlsFingerprint, want);

    // Only the HASH of the token is on the "server"; the token is nowhere.
    final env = File('${installDir()}/server.env').readAsStringSync();
    expect(env, contains('SYNC_ADMIN_TOKEN_SHA256=${c.sha256.convert(utf8.encode(res.adminToken!))}'));
    expect(allText(tmp), isNot(contains(res.adminToken!)), reason: 'token written nowhere (disk, shim logs)');
    expect(events.join('\n'), isNot(contains(res.adminToken!)));
    expect(tempLeft(), isEmpty, reason: 'remote temp directory removed');

    final cfg = res.toServerConfig();
    expect((cfg.serverUrl, cfg.adminToken, cfg.tlsFingerprint), (res.url, res.adminToken, res.tlsFingerprint));
    expect(events.any((e) => e.startsWith('running:')), isTrue, reason: 'stderr streamed as progress');
  });

  itest('rejected host key: nothing executed, nothing written', () async {
    await expectLater(Web3CInstaller().install(request(), onHostKey: (_) async => false), throwsA(isA<HostKeyRejected>()));
    expect(root.listSync(), isEmpty);
    expect(tempLeft(), isEmpty);
    expect(File('${state.path}/docker.log').existsSync(), isFalse);
  });

  itest('changed host key is a hard error, UI not consulted, nothing executed', () async {
    var asked = false;
    final wrong = 'SHA256:${base64.encode(List.filled(32, 1)).replaceAll('=', '')}';
    final e = await Web3CInstaller()
        .install(request(expected: wrong), onHostKey: (_) async => asked = true)
        .then<Object>((_) => 'no error', onError: (Object e) => e);
    expect(e, isA<HostKeyChanged>());
    expect((e as HostKeyChanged).presentedSha256, hostFp);
    expect(asked, isFalse);
    expect(root.listSync(), isEmpty);
    expect(tempLeft(), isEmpty);
  });

  itest('pinned key (no prompt); idempotent re-run has no token; status; upgrade; uninstall', () async {
    final inst = Web3CInstaller();
    Future<bool> never(HostKeyInfo _) async => throw StateError('must not prompt');
    final first = await inst.install(request(expected: hostFp), onHostKey: never);
    expect(first.adminToken, isNotNull);
    final second = await inst.install(request(expected: hostFp), onHostKey: never);
    expect(second.adminToken, isNull);
    expect(second.message, contains('déjà'));
    expect(second.tlsFingerprint, first.tlsFingerprint);
    expect(second.toServerConfig().adminToken, isNull);

    final st = await inst.status(request(expected: hostFp, tls: null), onHostKey: never);
    expect((st.running, st.healthy), (true, true));

    final up = await inst.upgrade(
        InstallRequest(
          host: '127.0.0.1',
          port: port,
          username: user,
          auth: PrivateKeyAuth(keyPem),
          sudo: SudoMode.none,
          instance: SyncInstance.iptv,
          image: 'ghcr.io/svax974/web3c-sync:2.0.0',
          expectedHostKeySha256: hostFp,
          remoteTempParent: rtmp.path,
          remoteEnvironment: request().remoteEnvironment,
        ),
        onHostKey: never);
    expect(up.adminToken, isNull);
    expect(File('${state.path}/docker.log').readAsStringSync(), contains('pull ghcr.io/svax974/web3c-sync:2.0.0'));

    final un = await inst.uninstall(request(expected: hostFp, tls: null), onHostKey: never);
    expect(un.message, contains('données conservées'));
    expect(Directory('${installDir()}/data').existsSync(), isTrue);
    expect(File('${installDir()}/server.env').existsSync(), isFalse);
    expect(tempLeft(), isEmpty);
  });

  itest('script failure surfaces typed: busy port', () async {
    File('${state.path}/listen').writeAsStringSync('0.0.0.0:443\n');
    await expectLater(Web3CInstaller().install(request(), onHostKey: (_) async => true), throwsA(isA<PortsBusy>()));
    expect(tempLeft(), isEmpty);
    expect(Directory('${root.path}/opt').existsSync(), isFalse);
  });

  itest('script failure surfaces typed: docker daemon down', () async {
    File('${state.path}/docker_down').writeAsStringSync('');
    await expectLater(Web3CInstaller().install(request(), onHostKey: (_) async => true), throwsA(isA<DockerMissing>()));
  });

  itest('passphrase-protected private key works', () async {
    final res = await Web3CInstaller().install(
        request(auth: PrivateKeyAuth(keyEncPem, passphrase: keyPass)),
        onHostKey: (_) async => true);
    expect(res.url, 'https://203.0.113.7');
  });

  itest('wrong passphrase is a request error that does not echo it', () async {
    final e = await Web3CInstaller()
        .install(request(auth: PrivateKeyAuth(keyEncPem, passphrase: 'WRONG-SENTINEL')), onHostKey: (_) async => true)
        .then<Object>((_) => 'no error', onError: (Object e) => e);
    expect(e, isA<InvalidRequest>());
    expect('$e', isNot(contains('WRONG-SENTINEL')));
  });

  itest('unauthorized key and (refused) password -> AuthFailed, secrets not echoed', () async {
    final stranger = File('${tmp.path}/stranger_key').readAsStringSync();
    await expectLater(Web3CInstaller().install(request(auth: PrivateKeyAuth(stranger)), onHostKey: (_) async => true),
        throwsA(isA<AuthFailed>()));
    final e = await Web3CInstaller()
        .install(request(auth: PasswordAuth('pw-SENTINEL-123')), onHostKey: (_) async => true)
        .then<Object>((_) => 'no error', onError: (Object e) => e);
    expect(e, isA<AuthFailed>());
    expect('$e', isNot(contains('SENTINEL')));
  });
}
