import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:web3c_sync/web3c_sync.dart';

import 'errors.dart';
import 'secrets.dart';

/// Pairing and membership of the device's sync group: create, join by
/// `web3c-link:v1`, members, revoke, leave, purge.
///
/// Owns the [Web3CSyncClient] (exposed as [client] once a group exists) and
/// persists the pairing in a [SyncSecretStore] under [keys]. Nothing here
/// touches the bookkeeping store. It is parameterised by the server
/// [instance] (`iptv` / `banking` / `aiteam`) and its [defaultServerUrl].
///
/// Pure Dart: no `ChangeNotifier`. A UI host wraps it and forwards
/// [onChanged] to its own `notifyListeners`; see the README.
///
/// **Errors are sanitised.** A failing operation sets [error] to
/// `describeSyncError(e)` and throws a [SyncEngineException] carrying that same
/// text: the raw exception could echo a pairing link (group key) or a server
/// URL in its `toString()`.
class SyncGroupController {
  SyncGroupController({
    required this.secrets,
    required this.keys,
    required this.instance,
    required this.defaultServerUrl,
    this.deviceName = 'Appareil',
    this.httpClientFactory,
    this.onChanged,
  });

  final SyncSecretStore secrets;

  /// Names of the pairing entries in [secrets].
  final SyncSecretKeys keys;
  final String instance;

  /// Server proposed when [createGroup] gets none.
  final String defaultServerUrl;
  final String deviceName;

  /// Test seam: the HTTP client given to every [Web3CSyncClient].
  final http.Client Function()? httpClientFactory;

  /// Called whenever the observable state ([busy], [error], [client]...)
  /// changes.
  void Function()? onChanged;

  /// Anti-rollback memory handed to every client (`SyncMetaStore.counterFloor`):
  /// the highest document counter `c` seen. May be assigned after construction
  /// (it is read at each call).
  int? Function(String collection, String docId)? counterFloor;

  Web3CSyncClient? _client;
  String? _serverUrl;
  bool _isOwner = false;
  String? _error;
  bool _busy = false;

  Web3CSyncClient? get client => _client;
  bool get hasGroup => _client?.groupId != null;
  String? get groupId => _client?.groupId;

  /// The server address. Sensitive for a personal server: show it only on
  /// explicit request, never log it.
  String? get serverUrl => _serverUrl;
  bool get isOwner => _isOwner;
  bool get busy => _busy;

  /// Last failure (sanitised); cleared by the next operation.
  String? get error => _error;

  /// Public key of this device (how it appears in [members]).
  String? get devicePub => _client?.deviceKey.publicKeyB64;

  void _notify() => onChanged?.call();

  DeviceKeyStore get _deviceKeys =>
      SecretStoreDeviceKeyStore(secrets, keys.deviceSeed);

  /// Restores the group persisted by an earlier run, if any.
  Future<void> load() async {
    final gid = await secrets.read(keys.groupId);
    final kg = await secrets.read(keys.groupKey);
    final server = await secrets.read(keys.server);
    if (gid == null || kg == null || server == null) return;
    final key = await _deviceKeys.loadOrCreate();
    _build(
      server: server,
      key: key,
      gid: gid,
      kg: base64Url.decode(base64Url.normalize(kg)),
      admin: await secrets.read(keys.adminToken),
      fp: await secrets.read(keys.tlsFingerprint),
    );
    _isOwner = await secrets.read(keys.isOwner) == 'true';
    _notify();
  }

  void _build({
    required String server,
    required DeviceKey key,
    String? gid,
    List<int>? kg,
    String? admin,
    String? fp,
  }) {
    _client?.close();
    _serverUrl = server;
    _client = Web3CSyncClient(
      baseUrl: server,
      instance: instance,
      deviceKey: key,
      groupId: gid,
      groupKey: kg,
      adminToken: admin,
      tlsFingerprint: fp,
      httpClient: httpClientFactory?.call(),
      counterFloor: (collection, docId) => counterFloor?.call(collection, docId),
    );
  }

  /// Runs [op] as one observable operation: [busy] while it runs, [error]
  /// cleared first and set (sanitised) on failure, which is rethrown as a
  /// [SyncEngineException]. Public so a host can add its own pairing flow.
  Future<T> run<T>(Future<T> Function() op) async {
    _busy = true;
    _error = null;
    _notify();
    try {
      return await op();
    } catch (e) {
      _error = describeSyncError(e);
      throw SyncEngineException(_error!, rollback: e is RollbackException);
    } finally {
      _busy = false;
      _notify();
    }
  }

  Future<void> _persist() async {
    final c = _client!;
    await secrets.write(keys.server, _serverUrl!);
    await secrets.write(keys.groupId, c.groupId!);
    await secrets.write(keys.groupKey, base64Url.encode(c.groupKey!));
    await secrets.write(keys.isOwner, '$_isOwner');
    if (c.adminToken != null) {
      await secrets.write(keys.adminToken, c.adminToken!);
    }
    if (c.tlsFingerprint != null) {
      await secrets.write(keys.tlsFingerprint, c.tlsFingerprint!);
    }
  }

  Future<void> _forget() async {
    for (final k in keys.pairing) {
      await secrets.delete(k);
    }
    _client?.close();
    _client = null;
    _isOwner = false;
  }

  /// Creates a new group (this device becomes its owner) on [serverUrl]
  /// (trimmed; [defaultServerUrl] when null or blank, unless
  /// [requireServerUrl]). [adminToken] is needed by personal servers that
  /// restrict creation; [tlsFingerprint] pins a self-signed certificate (both
  /// trimmed, blank means none, and both go to the secret store only).
  Future<void> createGroup({
    String? serverUrl,
    String? adminToken,
    String? tlsFingerprint,
    bool requireServerUrl = false,
  }) =>
      run(() async {
        final url = serverUrl?.trim() ?? '';
        if (url.isEmpty && requireServerUrl) {
          throw const SyncEngineException('server address missing');
        }
        final admin = adminToken?.trim() ?? '';
        final fp = tlsFingerprint?.trim() ?? '';
        final key = await _deviceKeys.loadOrCreate();
        _build(
          server: url.isEmpty ? defaultServerUrl : url,
          key: key,
          admin: admin.isEmpty ? null : admin,
          fp: fp.isEmpty ? null : fp,
        );
        try {
          await _client!.createGroup(deviceName: deviceName);
        } catch (_) {
          _client?.close();
          _client = null;
          rethrow;
        }
        _isOwner = true;
        await _persist();
      });

  /// A pairing link for a new device (QR / text). Single use, valid 10
  /// minutes. It embeds the group key: show it, never log or store it.
  Future<String> createJoinLink() =>
      run(() async => (await _client!.createJoinLink()).format());

  /// Joins the group a [link] (`web3c-link:v1?...&i=<instance>...`) points to.
  Future<void> join(String link) => run(() async {
        final l = GroupLink.parse(link);
        if (l.instance != instance) {
          throw SyncEngineException(
              'this pairing link is for another service (not "$instance")');
        }
        final key = await _deviceKeys.loadOrCreate();
        _build(
          server: l.server,
          key: key,
          gid: l.groupId,
          kg: l.groupKey,
          fp: l.tlsFingerprint,
        );
        try {
          await _client!.join(l.token, deviceName);
        } catch (_) {
          _client?.close();
          _client = null;
          rethrow;
        }
        _isOwner = false;
        await _persist();
      });

  Future<List<Member>> members() => run(() => _client!.members());

  /// Revokes another device (owner only). The group key is not rotated (see
  /// PROTOCOL 8): a revoked device that kept the key can read what it
  /// already has.
  Future<void> revoke(String devicePub) =>
      run(() async => _client!.revoke(devicePub));

  /// Leaves the group and forgets it on this device.
  Future<void> leave() => run(() async {
        try {
          await _client!.revoke(_client!.deviceKey.publicKeyB64);
        } on UnauthorizedException {
          // already revoked: leaving is what we want anyway
        } on ForbiddenException {
          // idem
        }
        await _forget();
      });

  /// Owner: deletes the group and everything in it on the server.
  Future<void> purgeGroup() => run(() async {
        await _client!.purgeGroup();
        await _forget();
      });

  /// Forgets the pairing on this device without telling the server (used when
  /// the server is unreachable or the user switches backend).
  Future<void> forgetLocally() async {
    await _forget();
    _notify();
  }

  /// Closes the client. The controller is not usable afterwards.
  void dispose() {
    _client?.close();
  }
}
