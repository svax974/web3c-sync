import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';

import 'errors.dart';
import 'hostkey.dart';
import 'models.dart';

/// Result of one remote command.
final class ExecResult {
  const ExecResult({required this.exitCode, required this.stdout, required this.stderrTail});
  final int? exitCode;
  final String stdout;

  /// Last few KiB of stderr (for diagnostics only; still unsanitized here).
  final String stderrTail;
}

/// A connected, authenticated, host-key-verified SSH connection.
abstract interface class RemoteConnection {
  /// Runs [command] (a string for the remote login shell), feeding [stdin]
  /// (then EOF). Each complete stderr line goes to [onStderrLine].
  Future<ExecResult> exec(
    String command, {
    List<int>? stdin,
    void Function(String line)? onStderrLine,
    Duration timeout,
  });

  Future<void> close();
}

/// Opens a [RemoteConnection]. The default uses `dartssh2`; tests inject fakes.
/// Implementations MUST call `verifier.verify` before authenticating and MUST
/// throw [HostKeyRejected]/[HostKeyChanged] (via `verifier.errorFor()`) when it
/// returned false.
typedef Connector = Future<RemoteConnection> Function(InstallRequest request, HostKeyVerifier verifier);

/// dartssh2-based connector (pure Dart SSH).
Future<RemoteConnection> connectWithDartssh2(InstallRequest request, HostKeyVerifier verifier) async {
  SSHClient? client;
  try {
    final socket = await SSHSocket.connect(request.host, request.port, timeout: request.connectTimeout);
    final auth = request.auth;
    var offered = false; // offer each secret once: no retry loop, no lockout
    List<SSHKeyPair>? identities;
    if (auth is PrivateKeyAuth) {
      try {
        identities = SSHKeyPair.fromPem(auth.pem.reveal(), auth.passphrase?.reveal());
      } catch (_) {
        socket.destroy();
        throw const InvalidRequest('privateKey', 'cannot be decoded (wrong passphrase or unsupported format)');
      }
    }
    client = SSHClient(
      socket,
      username: request.username,
      onVerifyHostKey: verifier.verify,
      identities: identities,
      onPasswordRequest: auth is PasswordAuth
          ? () {
              if (offered) return null;
              offered = true;
              return auth.secret.reveal();
            }
          : null,
      // PAM servers often ask for the password through keyboard-interactive.
      onUserInfoRequest: auth is PasswordAuth
          ? (req) {
              if (req.prompts.isEmpty) return <String>[];
              if (offered) return null;
              offered = true;
              return [for (final _ in req.prompts) auth.secret.reveal()];
            }
          : null,
    );
    await client.authenticated.timeout(request.connectTimeout + const Duration(seconds: 30));
    return _DartSshConnection(client);
  } on InstallerException {
    client?.close();
    rethrow;
  } catch (e) {
    client?.close();
    final fromKey = verifier.errorFor();
    if (fromKey != null) throw fromKey;
    if (e is SSHAuthError) throw const AuthFailed();
    if (e is SocketException || e is TimeoutException) {
      throw const ConnectionFailed('cannot reach the SSH server (network, port or firewall)');
    }
    if (e is SSHHostkeyError) throw const ConnectionFailed('SSH host key verification failed');
    // Never echo the underlying error text: it may carry user input.
    throw ConnectionFailed('SSH connection failed (${e.runtimeType})');
  }
}

final class _DartSshConnection implements RemoteConnection {
  _DartSshConnection(this._client);
  final SSHClient _client;

  @override
  Future<ExecResult> exec(
    String command, {
    List<int>? stdin,
    void Function(String line)? onStderrLine,
    Duration timeout = const Duration(minutes: 15),
  }) async {
    final session = await _client.execute(command);
    final out = StringBuffer();
    final err = StringBuffer();

    Future<void> pump(Stream<Uint8List> s, void Function(String line) onLine) {
      final c = Completer<void>();
      s.cast<List<int>>().transform(const Utf8Decoder(allowMalformed: true)).transform(const LineSplitter()).listen(
            onLine,
            onDone: c.complete,
            onError: (Object _) => c.complete(),
          );
      return c.future;
    }

    final outDone = pump(session.stdout, (l) => out.writeln(l));
    final errDone = pump(session.stderr, (l) {
      err.writeln(l);
      if (err.length > 8192) {
        final t = err.toString();
        err
          ..clear()
          ..write(t.substring(t.length - 4096));
      }
      onStderrLine?.call(l);
    });
    if (stdin != null) session.stdin.add(Uint8List.fromList(stdin));
    await session.stdin.close();
    try {
      await Future.wait([outDone, errDone, session.done]).timeout(timeout);
    } on TimeoutException {
      session.close();
      throw const ScriptFailed('TIMEOUT', 'the remote command did not finish in time');
    }
    return ExecResult(exitCode: session.exitCode, stdout: out.toString(), stderrTail: err.toString());
  }

  @override
  Future<void> close() async {
    _client.close();
    try {
      await _client.done.timeout(const Duration(seconds: 3));
    } catch (_) {}
  }
}
