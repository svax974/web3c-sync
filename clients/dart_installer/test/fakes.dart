import 'dart:convert';
import 'dart:typed_data';

import 'package:web3c_sync_installer/web3c_sync_installer.dart';

/// 32 zero-ish bytes -> a well-formed fingerprint.
String fpOf(int seed) => 'SHA256:${base64.encode(Uint8List.fromList(List.filled(32, seed))).replaceAll('=', '')}';

typedef ExecHandler = ExecResult Function(String command, List<int>? stdin, void Function(String)? onStderr);

class Call {
  Call(this.command, this.stdin);
  final String command;
  final List<int>? stdin;
}

class FakeConnection implements RemoteConnection {
  FakeConnection(this.handler, this.calls);
  final ExecHandler handler;
  final List<Call> calls;
  bool closed = false;

  @override
  Future<ExecResult> exec(String command, {List<int>? stdin, void Function(String line)? onStderrLine, Duration timeout = const Duration(minutes: 1)}) async {
    calls.add(Call(command, stdin == null ? null : List.of(stdin)));
    return handler(command, stdin, onStderrLine);
  }

  @override
  Future<void> close() async => closed = true;
}

/// Fake connector: presents [hostFp], runs the real TOFU verifier, then serves
/// commands with [handler]. mktemp returns /tmp/w3c-install.ABCDEF.
class FakeServer {
  FakeServer({required this.hostFp, required this.handler, this.authFails = false});
  final String hostFp;
  final ExecHandler handler;
  final bool authFails;
  final calls = <Call>[];
  FakeConnection? conn;
  int connects = 0;

  Connector get connector => (req, verifier) async {
        connects++;
        final ok = await verifier.verify('ssh-ed25519', Uint8List.fromList(utf8.encode(hostFp)));
        if (!ok) throw verifier.errorFor()!;
        if (authFails) throw const AuthFailed();
        return conn = FakeConnection((cmd, stdin, onErr) {
          if (cmd.contains('mktemp -d')) return const ExecResult(exitCode: 0, stdout: '/tmp/w3c-install.ABCDEF\n', stderrTail: '');
          if (cmd.startsWith('umask 077; cat >') || cmd.startsWith('rm -rf')) return const ExecResult(exitCode: 0, stdout: '', stderrTail: '');
          return handler(cmd, stdin, onErr);
        }, calls);
      };
}

ExecResult okResult(String json, {String stderr = ''}) =>
    ExecResult(exitCode: 0, stdout: 'WEB3C_RESULT $json\n', stderrTail: stderr);

const installOk =
    '{"ok":true,"action":"install","url":"https://203.0.113.7","instance":"iptv","adminToken":"TOKEN","tlsFingerprint":"FPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPFPF","imageDigest":"sha256:abc","version":"1.2.3","message":"installé"}';

InstallRequest req({
  Object? auth,
  SudoMode sudo = SudoMode.none,
  String? sudoPassword,
  String? expected,
  TlsMode? tls = const TlsMode.selfSigned(['203.0.113.7']),
  String? image,
  String? version,
  bool purge = false,
}) =>
    InstallRequest(
      host: '203.0.113.7',
      username: 'alice',
      auth: auth is SshAuth ? auth : PasswordAuth('ssh-pass-SENTINEL'),
      sudo: sudo,
      sudoPassword: sudoPassword == null ? null : Secret.fromString(sudoPassword),
      instance: SyncInstance.iptv,
      tls: tls,
      expectedHostKeySha256: expected,
      image: image,
      version: version,
      purgeData: purge,
    );
