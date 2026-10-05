import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'hostkey.dart';
import 'models.dart';
import 'redactor.dart';
import 'result_parser.dart';
import 'script_bundle.dart';
import 'transport.dart';

enum InstallPhase { connecting, uploading, running, cleaning }

/// Progress event; [message] is sanitized (no credential, no token).
final class InstallProgress {
  const InstallProgress(this.phase, this.message);
  final InstallPhase phase;
  final String message;
  @override
  String toString() => '${phase.name}: $message';
}

typedef ProgressCallback = void Function(InstallProgress progress);

const defaultImageRepository = 'ghcr.io/svax974/web3c-sync';

String _q(String s) => "'${s.replaceAll("'", "'\\''")}'";

/// Installs and manages the web3c-sync personal server over SSH.
///
/// Every operation opens ONE SSH connection, verifies the host key (TOFU, see
/// [HostKeyVerifier]), uploads the embedded `install.sh` + templates to a 0700
/// temporary directory on the host, runs it (through `sudo` if requested),
/// streams its stderr as progress, parses the `WEB3C_RESULT` line, removes the
/// temporary directory and wipes the credentials.
final class Web3CInstaller {
  Web3CInstaller({Connector? connector, ScriptBundle? bundle})
      : _connect = connector ?? connectWithDartssh2,
        _bundle = bundle ?? ScriptBundle.embedded();

  final Connector _connect;
  final ScriptBundle _bundle;

  /// First installation (or idempotent re-run: then `adminToken` is null).
  Future<InstallResult> install(
    InstallRequest request, {
    required HostKeyConfirm onHostKey,
    ProgressCallback? onProgress,
  }) async {
    if (request.tls == null) {
      request.wipe();
      throw const InvalidRequest('tls', 'required for install');
    }
    final r = await _run(request, '--install', onHostKey, onProgress);
    return _installResult(r.$1, r.$2);
  }

  Future<ServerStatus> status(
    InstallRequest request, {
    required HostKeyConfirm onHostKey,
    ProgressCallback? onProgress,
  }) async {
    final (res, hk) = await _run(request, '--status', onHostKey, onProgress);
    return ServerStatus(
      url: res.str('url') ?? '',
      instance: res.str('instance') ?? request.instance.name,
      running: res.flag('running') ?? false,
      healthy: res.flag('healthy') ?? false,
      imageDigest: res.str('imageDigest') ?? '',
      version: res.str('version') ?? '',
      tlsFingerprint: res.str('tlsFingerprint'),
      hostKeySha256: hk,
    );
  }

  /// New image (`request.image`/`version`), data kept; rolls back on failure.
  Future<InstallResult> upgrade(
    InstallRequest request, {
    required HostKeyConfirm onHostKey,
    ProgressCallback? onProgress,
  }) async {
    final r = await _run(request, '--upgrade', onHostKey, onProgress);
    return _installResult(r.$1, r.$2);
  }

  /// Keeps the data unless `request.purgeData`.
  Future<UninstallResult> uninstall(
    InstallRequest request, {
    required HostKeyConfirm onHostKey,
    ProgressCallback? onProgress,
  }) async {
    final (res, hk) = await _run(request, '--uninstall', onHostKey, onProgress);
    return UninstallResult(message: res.str('message') ?? '', hostKeySha256: hk);
  }

  InstallResult _installResult(ScriptResult r, String hostKey) {
    final url = r.str('url');
    if (url == null || !url.startsWith('https://')) {
      throw const ScriptFailed('BAD_RESULT', 'the script returned no valid https URL');
    }
    return InstallResult(
      url: url,
      instance: r.str('instance') ?? '',
      adminToken: r.str('adminToken'),
      tlsFingerprint: r.str('tlsFingerprint'),
      imageDigest: r.str('imageDigest') ?? '',
      version: r.str('version') ?? '',
      hostKeySha256: hostKey,
      message: r.str('message') ?? '',
    );
  }

  List<String> _scriptArgs(InstallRequest q, String action) {
    final a = <String>[action, '--instance', q.instance.name];
    final t = q.tls;
    if (action == '--install') {
      switch (t!) {
        case final DomainTls d:
          a.addAll(['--tls', 'domain=${d.name}']);
          if (d.email != null) a.addAll(['--email', d.email!]);
        case final SelfSignedTls ss:
          a.addAll(['--tls', 'selfsigned', '--host', ss.hosts.join(',')]);
      }
      if (q.installDocker) a.add('--install-docker');
    }
    if (action == '--install' || action == '--upgrade') {
      var img = q.image;
      final v = q.version;
      if (v != null) {
        img ??= defaultImageRepository;
        final last = img.split('/').last;
        if (!img.contains('@') && !last.contains(':')) img = '$img:$v';
      }
      if (img != null) a.addAll(['--image', img]);
    }
    if (action == '--uninstall' && q.purgeData) a.add('--purge-data');
    return a;
  }

  Future<(ScriptResult, String)> _run(
    InstallRequest q,
    String action,
    HostKeyConfirm onHostKey,
    ProgressCallback? onProgress,
  ) async {
    q.markUsed();
    final red = Redactor();
    void emit(InstallPhase p, String m) => onProgress?.call(InstallProgress(p, red.clean(m)));

    RemoteConnection? conn;
    String? tmp;
    try {
      // Secrets known to the redactor for the whole call (revealed Strings are
      // not retained beyond it).
      final a = q.auth;
      if (a is PasswordAuth) red.add(a.secret.reveal());
      if (a is PrivateKeyAuth) red.add(a.passphrase?.reveal());
      red.add(q.sudoSecret?.reveal());

      final verifier = HostKeyVerifier(onHostKey: onHostKey, expectedSha256: q.expectedHostKeySha256);
      final args = _scriptArgs(q, action);

      emit(InstallPhase.connecting, 'connecting to the SSH server');
      conn = await _connect(q, verifier);
      final hostKey = verifier.presented ?? '';
      emit(InstallPhase.connecting, 'host key accepted ($hostKey)');

      // Private temporary directory (0700), created by the user on the host.
      final mk = await conn.exec(
        "umask 077; mktemp -d ${_q('${q.remoteTempParent == '/' ? '' : q.remoteTempParent}/w3c-install.XXXXXX')}",
        timeout: const Duration(seconds: 30),
      );
      final dir = mk.stdout.trim();
      final dirRe = RegExp('^${RegExp.escape(q.remoteTempParent == '/' ? '' : q.remoteTempParent)}/w3c-install\\.[A-Za-z0-9]{4,}\$');
      if (mk.exitCode != 0 || !dirRe.hasMatch(dir)) {
        throw const ScriptFailed('REMOTE_TEMP', 'cannot create the temporary directory on the host');
      }
      tmp = dir;

      emit(InstallPhase.uploading, 'sending the installation script');
      for (final f in _bundle.files.entries) {
        final up = await conn.exec('umask 077; cat > ${_q('$dir/${f.key}')}', stdin: f.value, timeout: const Duration(seconds: 60));
        if (up.exitCode != 0) throw const ScriptFailed('UPLOAD', 'cannot write the script on the host');
      }

      // sudo password goes to sudo's stdin; NEVER on a command line.
      final env = q.remoteEnvironment.entries.map((e) => '${e.key}=${_q(e.value)}').toList();
      final inner = ['env', ...env, 'sh', _q('$dir/install.sh'), ...args.map(_q)].join(' ');
      Uint8List? stdin;
      String cmd;
      switch (q.sudo) {
        case SudoMode.none:
          cmd = inner;
        case SudoMode.nopasswd:
          cmd = 'sudo -n -- $inner';
        case SudoMode.password:
          cmd = "sudo -S -p '' -k -- $inner";
          stdin = Uint8List.fromList([...utf8.encode(q.sudoSecret!.reveal()), 10]);
      }

      emit(InstallPhase.running, 'running the installer on the host');
      final ExecResult run;
      try {
        run = await conn.exec(
          cmd,
          stdin: stdin,
          onStderrLine: (l) => emit(InstallPhase.running, l),
          timeout: q.commandTimeout,
        );
      } finally {
        stdin?.fillRange(0, stdin.length, 0);
      }
      final result = parseResult(run.stdout);
      if (result == null) {
        throw _noResult(q, run, red);
      }
      if (!result.ok) throw errorFromResult(result, red);
      return (result, hostKey);
    } on InstallerException {
      rethrow;
    } finally {
      if (conn != null) {
        if (tmp != null) {
          emit(InstallPhase.cleaning, 'removing the temporary directory');
          try {
            await conn.exec('rm -rf -- ${_q(tmp)}', timeout: const Duration(seconds: 30));
          } catch (_) {/* best effort */}
        }
        try {
          await conn.close();
        } catch (_) {}
      }
      q.wipe();
    }
  }

  InstallerException _noResult(InstallRequest q, ExecResult run, Redactor red) {
    final err = run.stderrTail.toLowerCase();
    if (q.sudo != SudoMode.none) {
      if (err.contains('incorrect password') ||
          err.contains('sorry, try again') ||
          err.contains('no password was provided')) {
        return const SudoFailed('sudo refused the password');
      }
      if (err.contains('password is required') || err.contains('no tty present')) {
        return const SudoFailed('sudo needs a password (NOPASSWD is not configured)');
      }
      if (err.contains('not in the sudoers') || err.contains('may not run sudo')) {
        return const SudoFailed('this user is not allowed to use sudo');
      }
      if (err.contains('sudo: not found') || err.contains('sudo: command not found')) {
        return const SudoFailed('sudo is not installed on the host');
      }
    }
    return ScriptFailed('NO_RESULT', 'the script ended without a result (exit code ${run.exitCode})');
  }
}
