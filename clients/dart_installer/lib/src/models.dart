import 'errors.dart';
import 'secret.dart';

/// Server instance: one per use (spec/PROTOCOL.md).
enum SyncInstance { iptv, banking, aiteam }

/// How the installed server is reached over TLS.
sealed class TlsMode {
  const TlsMode();

  /// Public name: Caddy obtains a Let's Encrypt certificate (ports 80/443 must
  /// be reachable from the Internet and the DNS must point to the host).
  const factory TlsMode.domain(String name, {String? email}) = DomainTls;

  /// No domain: self-signed certificate (10 years) for [hosts] (IP addresses
  /// and/or names, the first one becomes the URL). The app pins its
  /// fingerprint.
  const factory TlsMode.selfSigned(List<String> hosts) = SelfSignedTls;
}

final class DomainTls extends TlsMode {
  const DomainTls(this.name, {this.email});
  final String name;
  final String? email;
}

final class SelfSignedTls extends TlsMode {
  const SelfSignedTls(this.hosts);
  final List<String> hosts;
}

/// How the remote command gets root.
enum SudoMode {
  /// Run as is (SSH user is root).
  none,

  /// `sudo` without password (NOPASSWD).
  nopasswd,

  /// `sudo -S`: the password is written to sudo's standard input, never on a
  /// command line.
  password,
}

/// SSH credentials. Secrets are held in [Secret] buffers wiped after the call.
sealed class SshAuth {
  const SshAuth();
}

final class PasswordAuth extends SshAuth {
  PasswordAuth(String password) : secret = Secret.fromString(password);
  final Secret secret;
}

final class PrivateKeyAuth extends SshAuth {
  PrivateKeyAuth(String pem, {String? passphrase})
      : pem = Secret.fromString(pem),
        passphrase = passphrase == null ? null : Secret.fromString(passphrase);
  final Secret pem;
  final Secret? passphrase;
}

final _hostRe = RegExp(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|[0-9A-Fa-f:]*:[0-9A-Fa-f:]*)$');
final _userRe = RegExp(r'^[A-Za-z_][A-Za-z0-9._-]{0,31}$');
final _refRe = RegExp(r'^[A-Za-z0-9][A-Za-z0-9._/:@-]*$');
final _pathRe = RegExp(r'^/[A-Za-z0-9._/-]*$');
final _envKeyRe = RegExp(r'^[A-Z_][A-Z0-9_]*$');

/// Everything needed for one operation. The credentials are valid for ONE call:
/// the installer wipes them when the call ends, and the request cannot be
/// reused afterwards (build a new one, asking the user again).
final class InstallRequest {
  InstallRequest({
    required this.host,
    this.port = 22,
    required this.username,
    required this.auth,
    this.sudo = SudoMode.password,
    Secret? sudoPassword,
    required this.instance,
    this.tls,
    this.image,
    this.version,
    this.installDocker = false,
    this.purgeData = false,
    this.expectedHostKeySha256,
    this.remoteEnvironment = const {},
    this.remoteTempParent = '/tmp',
    this.connectTimeout = const Duration(seconds: 15),
    this.commandTimeout = const Duration(minutes: 15),
  }) : _sudoPassword = sudoPassword {
    if (!_hostRe.hasMatch(host)) throw const InvalidRequest('host', 'invalid');
    if (port < 1 || port > 65535) throw const InvalidRequest('port', 'out of range');
    if (!_userRe.hasMatch(username)) throw const InvalidRequest('username', 'invalid');
    final i = image;
    if (i != null && !_refRe.hasMatch(i)) throw const InvalidRequest('image', 'invalid reference');
    final v = version;
    if (v != null && !RegExp(r'^[A-Za-z0-9._-]{1,128}$').hasMatch(v)) {
      throw const InvalidRequest('version', 'invalid');
    }
    for (final e in remoteEnvironment.entries) {
      if (!_envKeyRe.hasMatch(e.key)) throw const InvalidRequest('remoteEnvironment', 'invalid variable name');
    }
    if (!_pathRe.hasMatch(remoteTempParent) || remoteTempParent.contains('..')) {
      throw const InvalidRequest('remoteTempParent', 'invalid');
    }
    final t = tls;
    if (t is DomainTls) {
      if (!RegExp(r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$').hasMatch(t.name)) {
        throw const InvalidRequest('tls.domain', 'invalid');
      }
      if (t.email != null && !RegExp(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$').hasMatch(t.email!)) {
        throw const InvalidRequest('tls.email', 'invalid');
      }
    } else if (t is SelfSignedTls) {
      if (t.hosts.isEmpty) throw const InvalidRequest('tls.hosts', 'at least one host or IP');
      for (final h in t.hosts) {
        if (!_hostRe.hasMatch(h)) throw const InvalidRequest('tls.hosts', 'invalid entry');
      }
    }
    if (sudo == SudoMode.password && auth is! PasswordAuth && sudoPassword == null) {
      throw const InvalidRequest('sudoPassword', 'required when SSH uses a key and sudo needs a password');
    }
  }

  final String host;
  final int port;
  final String username;
  final SshAuth auth;
  final SudoMode sudo;
  final Secret? _sudoPassword;
  final SyncInstance instance;

  /// Required by `install` (and used to name the URL); not needed otherwise.
  final TlsMode? tls;

  /// Full image reference (tag or `@sha256:` digest). Default: the script's.
  final String? image;

  /// Convenience tag appended to [image] (or to the default image) when that
  /// reference carries no tag/digest.
  final String? version;
  final bool installDocker;
  final bool purgeData;

  /// SHA-256 fingerprint confirmed on a previous connection (`SHA256:...`,
  /// base64 or hex). When set, a different key is a hard [HostKeyChanged].
  final String? expectedHostKeySha256;

  /// Extra environment for the remote script (`env K=V`). For advanced use and
  /// tests (e.g. `W3C_DEFAULT_IMAGE`). Never put secrets here: it appears on
  /// the remote command line.
  final Map<String, String> remoteEnvironment;

  /// Parent of the 0700 temporary directory created on the host.
  final String remoteTempParent;
  final Duration connectTimeout;
  final Duration commandTimeout;

  bool _consumed = false;

  /// Password used for `sudo -S`: the explicit one, else the SSH password.
  Secret? get sudoSecret {
    if (sudo != SudoMode.password) return null;
    return _sudoPassword ?? (auth is PasswordAuth ? (auth as PasswordAuth).secret : null);
  }

  /// Marks the request as used and refuses a second use.
  void markUsed() {
    if (_consumed) {
      throw StateError('InstallRequest already used: its credentials were wiped; create a new one');
    }
    _consumed = true;
  }

  /// Overwrites every credential buffer. Called by the installer in `finally`.
  void wipe() {
    final a = auth;
    switch (a) {
      case PasswordAuth():
        a.secret.wipe();
      case PrivateKeyAuth():
        a.pem.wipe();
        a.passphrase?.wipe();
    }
    _sudoPassword?.wipe();
  }

  @override
  String toString() => 'InstallRequest($username@$host:$port, ${instance.name}, credentials: ***)';
}

/// Server configuration as consumed by the "Serveur personnel" selector.
///
/// It maps 1:1 onto `Web3CGroupController.createGroup(serverUrl:, adminToken:,
/// tlsFingerprint:)` (packages/vxiptv_sync) and onto `Web3CSyncClient(baseUrl:,
/// adminToken:, tlsFingerprint:, instance:)`. The admin token must be stored in
/// the device's secure storage (design plan §7) and never synchronized.
final class PersonalServerConfig {
  const PersonalServerConfig({
    required this.serverUrl,
    required this.instance,
    this.adminToken,
    this.tlsFingerprint,
  });

  final String serverUrl;
  final String instance;

  /// Null when the server was already installed (the token is shown only once).
  final String? adminToken;

  /// base64url SHA-256 of the leaf certificate; null with a public (Let's
  /// Encrypt) certificate. Accepted by `parseFingerprint` of `web3c_sync`.
  final String? tlsFingerprint;

  @override
  String toString() => 'PersonalServerConfig($serverUrl, $instance, adminToken: ${adminToken == null ? 'none' : '***'}, tls: ${tlsFingerprint ?? 'public CA'})';
}

/// Outcome of `install` / `upgrade`.
final class InstallResult {
  const InstallResult({
    required this.url,
    required this.instance,
    this.adminToken,
    this.tlsFingerprint,
    required this.imageDigest,
    required this.version,
    required this.hostKeySha256,
    this.message = '',
  });

  final String url;
  final String instance;

  /// Present ONLY on the first installation. The package never prints it.
  final String? adminToken;
  final String? tlsFingerprint;
  final String imageDigest;
  final String version;

  /// SSH host key fingerprint (`SHA256:...`) seen during this operation; keep
  /// it as `expectedHostKeySha256` for later operations.
  final String hostKeySha256;
  final String message;

  PersonalServerConfig toServerConfig() => PersonalServerConfig(
        serverUrl: url,
        instance: instance,
        adminToken: adminToken,
        tlsFingerprint: tlsFingerprint,
      );

  @override
  String toString() => 'InstallResult($url, $instance, version: $version, adminToken: ${adminToken == null ? 'none' : '***'})';
}

/// Outcome of `status`.
final class ServerStatus {
  const ServerStatus({
    required this.url,
    required this.instance,
    required this.running,
    required this.healthy,
    required this.imageDigest,
    required this.version,
    this.tlsFingerprint,
    required this.hostKeySha256,
  });
  final String url;
  final String instance;
  final bool running;
  final bool healthy;
  final String imageDigest;
  final String version;
  final String? tlsFingerprint;
  final String hostKeySha256;
}

/// Outcome of `uninstall`.
final class UninstallResult {
  const UninstallResult({required this.message, required this.hostKeySha256});
  final String message;
  final String hostKeySha256;
}
