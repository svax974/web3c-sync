import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'crypto.dart' as c;
import 'device_key.dart';
import 'errors.dart';
import 'group_link.dart';
import 'tls_pinning.dart';

/// Collection used for encrypted device names (join / members).
const nameCollection = '_name';

class JoinToken {
  const JoinToken(this.token, this.expiresAt);
  final String token;
  final int expiresAt;
}

class Member {
  const Member({
    required this.device,
    required this.nameEnc,
    required this.name,
    required this.owner,
    required this.joinedAt,
  });
  final String device;
  final String nameEnc;

  /// Decrypted device name, or null if it cannot be decrypted.
  final String? name;
  final bool owner;
  final int joinedAt;
}

class GroupInfo {
  const GroupInfo({
    required this.instance,
    required this.seq,
    required this.docs,
    required this.bytes,
    required this.members,
    required this.purgeAt,
    required this.quota,
  });
  final String instance;
  final int seq;
  final int docs;
  final int bytes;
  final int? members;
  final int purgeAt;
  final Map<String, dynamic> quota;
}

/// A decrypted document.
class DocRecord {
  const DocRecord({
    required this.collection,
    required this.logicalId,
    required this.docId,
    required this.payload,
    required this.updatedAt,
    required this.seq,
  });
  final String collection;
  final String logicalId;
  final String docId;
  final Object? payload;

  /// Inner `u` (epoch ms), set by the writing client.
  final int updatedAt;
  final int seq;
}

sealed class ChangeItem {
  const ChangeItem(this.collection, this.docId, this.seq);
  final String collection;
  final String docId;
  final int seq;
}

class DocChange extends ChangeItem {
  DocChange(this.record) : super(record.collection, record.docId, record.seq);
  final DocRecord record;
}

class Tombstone extends ChangeItem {
  const Tombstone(super.collection, super.docId, super.seq);
}

/// An item that could not be decrypted or failed the docId integrity check
/// (wrong group key, tampering). It never aborts the page.
class Undecryptable extends ChangeItem {
  const Undecryptable(super.collection, super.docId, super.seq, this.error);
  final Object error;
}

class ChangesPage {
  const ChangesPage(this.items, this.next, this.more);
  final List<ChangeItem> items;
  final int next;
  final bool more;
}

class SyncEvent {
  const SyncEvent(this.collection, this.docId, this.seq, this.deleted);
  final String collection;
  final String docId;
  final int seq;
  final bool deleted;
}

/// A payload and its inner timestamp, as handled by [Web3CSyncClient.upsert].
class Versioned {
  const Versioned(this.payload, this.updatedAt);
  final Object? payload;
  final int updatedAt;
}

typedef MergeFn = Versioned Function(Versioned local, Versioned remote);

/// The most recent inner `updatedAt` wins; remote wins ties.
Versioned lastWriteWins(Versioned local, Versioned remote) =>
    local.updatedAt > remote.updatedAt ? local : remote;

class Web3CSyncClient {
  Web3CSyncClient({
    required String baseUrl,
    required this.instance,
    required this.deviceKey,
    this.groupId,
    List<int>? groupKey,
    this.adminToken,
    this.tlsFingerprint,
    http.Client? httpClient,
    DateTime Function()? clock,
    this.sseBackoffMin = const Duration(seconds: 1),
    this.sseBackoffMax = const Duration(seconds: 30),
    this.sseIdleTimeout = const Duration(seconds: 70),
  })  : baseUrl = baseUrl.replaceFirst(RegExp(r'/+$'), ''),
        _http = httpClient ??
            (tlsFingerprint != null
                ? pinnedHttpClient(tlsFingerprint)
                : http.Client()),
        _clock = clock ?? DateTime.now {
    this.groupKey = groupKey;
  }

  final String baseUrl;
  final String instance;
  final DeviceKey deviceKey;
  final String? adminToken;
  final String? tlsFingerprint;
  final Duration sseBackoffMin, sseBackoffMax, sseIdleTimeout;
  final http.Client _http;
  final DateTime Function() _clock;

  String? groupId;
  List<int>? _groupKey;
  c.DerivedKeys? _keys;

  List<int>? get groupKey => _groupKey;
  set groupKey(List<int>? k) {
    if (k != null && k.length != 32) {
      throw ArgumentError('K_g must be 32 bytes');
    }
    _groupKey = k == null ? null : Uint8List.fromList(k);
    _keys = k == null ? null : c.deriveKeys(k);
  }

  void close() => _http.close();

  String get _gid =>
      groupId ?? (throw StateError('groupId is not set on this client'));
  c.DerivedKeys get _k =>
      _keys ?? (throw StateError('groupKey is not set on this client'));

  // ---------- transport ----------

  Future<Map<String, String>> _signedHeaders(
    String method,
    String pathQuery,
    List<int> body,
  ) async {
    final ts = (_clock().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = c.b64(c.randomBytes(16));
    final canon = c.canonicalRequest(
      method: method,
      pathQuery: pathQuery,
      timestamp: ts,
      nonce: nonce,
      bodyHash: c.bodyHash(body),
      instance: instance,
    );
    return {
      'X-Device': deviceKey.publicKeyB64,
      'X-Timestamp': ts,
      'X-Nonce': nonce,
      'X-Signature': c.b64(await deviceKey.sign(canon)),
    };
  }

  /// The signed string must carry exactly the request-target that goes on the
  /// wire, so it is taken from the final [Uri].
  (Uri, String) _target(String pathQuery) {
    final uri = Uri.parse('$baseUrl$pathQuery');
    final target = uri.hasQuery ? '${uri.path}?${uri.query}' : uri.path;
    return (uri, target);
  }

  Future<http.Request> _request(
    String method,
    String pathQuery, {
    List<int> body = const [],
    Map<String, String> headers = const {},
  }) async {
    final (uri, target) = _target(pathQuery);
    final req = http.Request(method, uri)..bodyBytes = body;
    req.headers.addAll(headers);
    req.headers.addAll(await _signedHeaders(method, target, body));
    return req;
  }

  Future<http.Response> _send(
    String method,
    String pathQuery, {
    List<int> body = const [],
    Map<String, String> headers = const {},
    bool throwOnError = true,
  }) async {
    final req = await _request(method, pathQuery, body: body, headers: headers);
    final res = await http.Response.fromStream(await _http.send(req));
    if (throwOnError) checkResponse(res);
    return res;
  }

  Map<String, dynamic> _json(http.Response r) =>
      jsonDecode(utf8.decode(r.bodyBytes)) as Map<String, dynamic>;

  // ---------- groups ----------

  /// Creates the group. Generates a groupId / K_g when the client has none.
  ///
  /// [deviceName], when given, is stored encrypted with K_name so the owner is
  /// listed by name in [members].
  Future<String> createGroup({String? deviceName}) async {
    groupId ??= GroupLink.generateGroupId();
    groupKey ??= GroupLink.generateGroupKey();
    final nameEnc = deviceName == null
        ? null
        : await _sealName(deviceName, deviceKey.publicKeyB64);
    await _send(
      'POST',
      '/v1/g',
      body: utf8.encode(jsonEncode(
          {'groupId': groupId, if (nameEnc != null) 'nameEnc': nameEnc})),
      headers: {
        'Content-Type': 'application/json',
        if (adminToken != null) 'Authorization': 'Bearer $adminToken',
      },
    );
    return groupId!;
  }

  Future<JoinToken> createJoinToken() async {
    final j = _json(await _send('POST', '/v1/g/$_gid/join-tokens'));
    return JoinToken(j['token'] as String, (j['expiresAt'] as num).toInt());
  }

  /// Owner helper: mints a token and returns the pairing link (embeds K_g).
  Future<GroupLink> createJoinLink() async {
    final t = await createJoinToken();
    return GroupLink(
      server: baseUrl,
      instance: instance,
      groupId: _gid,
      token: t.token,
      groupKey: _groupKey!,
      tlsFingerprint: tlsFingerprint,
    );
  }

  /// Joins [groupId] with [token]; the device name is encrypted with K_name.
  Future<void> join(String token, String deviceName) async {
    final nameEnc = await _sealName(deviceName, deviceKey.publicKeyB64);
    await _send(
      'POST',
      '/v1/g/$_gid/join',
      body: utf8.encode(jsonEncode({'token': token, 'nameEnc': nameEnc})),
      headers: {'Content-Type': 'application/json'},
    );
  }

  // Spec 6.2 does not say which docId binds the name envelope; the device's
  // public key (b64url) is used so a name cannot be moved between devices.
  Future<String> _sealName(String name, String devicePub) async => c.b64(
        await c.seal(
          _k.name,
          c.aad(instance, _gid, nameCollection, devicePub),
          utf8.encode(name),
        ),
      );

  Future<String?> _openName(String nameEnc, String devicePub) async {
    try {
      final p = await c.open(
        _k.name,
        c.aad(instance, _gid, nameCollection, devicePub),
        c.unb64(nameEnc),
      );
      return utf8.decode(p);
    } catch (_) {
      return null;
    }
  }

  Future<List<Member>> members() async {
    final res = await _send('GET', '/v1/g/$_gid/members');
    final list = jsonDecode(utf8.decode(res.bodyBytes)) as List;
    return [
      for (final m in list.cast<Map<String, dynamic>>())
        Member(
          device: m['device'] as String,
          nameEnc: (m['nameEnc'] as String?) ?? '',
          name: _keys == null
              ? null
              : await _openName(
                  (m['nameEnc'] as String?) ?? '', m['device'] as String),
          owner: m['owner'] as bool,
          joinedAt: (m['joinedAt'] as num).toInt(),
        ),
    ];
  }

  /// Revokes [devicePub] (owner) or leaves the group (own key).
  Future<void> revoke(String devicePub) =>
      _send('DELETE', '/v1/g/$_gid/members/$devicePub');

  Future<GroupInfo> info() async {
    final j = _json(await _send('GET', '/v1/g/$_gid/info'));
    return GroupInfo(
      instance: j['instance'] as String,
      seq: (j['seq'] as num).toInt(),
      docs: (j['docs'] as num).toInt(),
      bytes: (j['bytes'] as num).toInt(),
      members: (j['members'] as num?)?.toInt(),
      purgeAt: (j['purgeAt'] as num).toInt(),
      quota: (j['quota'] as Map?)?.cast<String, dynamic>() ?? const {},
    );
  }

  Future<void> purgeGroup() => _send('DELETE', '/v1/g/$_gid');

  // ---------- documents ----------

  String docIdFor(String collection, String logicalId) =>
      c.docId(_k.id, collection, logicalId);

  String _docPath(String collection, String docId) =>
      '/v1/g/$_gid/d/$collection/$docId';

  /// Writes a document and returns its new seq. [ifMatchSeq] is 0 for a
  /// creation, otherwise the seq the caller based its change on (the
  /// tombstone's seq to re-create a deleted document).
  Future<int> putDoc(
    String collection,
    String logicalId,
    Object? payload, {
    required int updatedAt,
    required int ifMatchSeq,
  }) async {
    final id = docIdFor(collection, logicalId);
    final plain = utf8.encode(jsonEncode({
      'v': 1,
      'u': updatedAt,
      'k': logicalId,
      'd': payload,
    }));
    final env = await c.seal(
      _k.enc,
      c.aad(instance, _gid, collection, id),
      plain,
    );
    final res = await _send(
      'PUT',
      _docPath(collection, id),
      body: env,
      headers: {
        'If-Match': '$ifMatchSeq',
        'Content-Type': 'application/octet-stream',
      },
    );
    return (_json(res)['seq'] as num).toInt();
  }

  /// Fetches and decrypts a document. Throws [NotFoundException],
  /// [GoneException] (tombstone), [DecryptException] or [IntegrityException].
  Future<DocRecord> getDoc(String collection, String logicalId) async {
    final id = docIdFor(collection, logicalId);
    final res = await _send('GET', _docPath(collection, id));
    final seq = int.tryParse(res.headers['x-seq'] ?? '') ?? -1;
    return _decryptDoc(collection, id, res.bodyBytes, seq);
  }

  Future<DocRecord> _decryptDoc(
    String collection,
    String docId,
    List<int> env,
    int seq,
  ) async {
    final plain = await c.open(
      _k.enc,
      c.aad(instance, _gid, collection, docId),
      env,
    );
    final Object? j;
    try {
      j = jsonDecode(utf8.decode(plain));
    } on FormatException {
      throw const c.DecryptException();
    }
    if (j is! Map || j['v'] != 1 || j['k'] is! String || j['u'] is! num) {
      throw const c.DecryptException();
    }
    final k = j['k'] as String;
    // The server could swap documents between identifiers: bind k to docId.
    if (c.docId(_k.id, collection, k) != docId) {
      throw const IntegrityException();
    }
    return DocRecord(
      collection: collection,
      logicalId: k,
      docId: docId,
      payload: j['d'],
      updatedAt: (j['u'] as num).toInt(),
      seq: seq,
    );
  }

  /// Deletes a document (tombstone); returns the tombstone's seq.
  Future<int> deleteDoc(
    String collection,
    String logicalId, {
    required int ifMatchSeq,
  }) async {
    final res = await _send(
      'DELETE',
      _docPath(collection, docIdFor(collection, logicalId)),
      headers: {'If-Match': '$ifMatchSeq'},
    );
    return (_json(res)['seq'] as num).toInt();
  }

  /// Optimistic read-merge-write. Writes [payload] (stamped [updatedAt], now by
  /// default); when a remote version exists, [merge] decides (default:
  /// [lastWriteWins]). On 409 the remote is re-read and merged again, up to
  /// [maxAttempts]. If the merge keeps the remote unchanged nothing is written.
  Future<DocRecord> upsert(
    String collection,
    String logicalId,
    Object? payload, {
    int? updatedAt,
    MergeFn merge = lastWriteWins,
    int maxAttempts = 5,
  }) async {
    final local =
        Versioned(payload, updatedAt ?? _clock().millisecondsSinceEpoch);
    ConflictException? last;
    for (var i = 0; i < maxAttempts; i++) {
      var seq = 0;
      var toWrite = local;
      try {
        final remote = await getDoc(collection, logicalId);
        seq = remote.seq;
        final r = Versioned(remote.payload, remote.updatedAt);
        toWrite = merge(local, r);
        if (identical(toWrite, r) ||
            (toWrite.updatedAt == r.updatedAt &&
                jsonEncode(toWrite.payload) == jsonEncode(r.payload))) {
          return remote;
        }
      } on NotFoundException {
        seq = 0;
      } on GoneException catch (g) {
        seq = g.seq;
      }
      try {
        final newSeq = await putDoc(
          collection,
          logicalId,
          toWrite.payload,
          updatedAt: toWrite.updatedAt,
          ifMatchSeq: seq,
        );
        return DocRecord(
          collection: collection,
          logicalId: logicalId,
          docId: docIdFor(collection, logicalId),
          payload: toWrite.payload,
          updatedAt: toWrite.updatedAt,
          seq: newSeq,
        );
      } on ConflictException catch (e) {
        last = e;
      }
    }
    throw last!;
  }

  // ---------- changes / stream ----------

  Future<ChangesPage> changes(int since, {int limit = 500}) async {
    final res = await _send(
      'GET',
      '/v1/g/$_gid/changes?since=$since&limit=$limit',
    );
    final j = _json(res);
    final items = <ChangeItem>[];
    for (final it in (j['items'] as List).cast<Map<String, dynamic>>()) {
      final coll = it['collection'] as String;
      final id = it['docId'] as String;
      final seq = (it['seq'] as num).toInt();
      if (it['deleted'] == true) {
        items.add(Tombstone(coll, id, seq));
        continue;
      }
      try {
        final env = c.unb64(it['env'] as String);
        items.add(DocChange(await _decryptDoc(coll, id, env, seq)));
      } catch (e) {
        items.add(Undecryptable(coll, id, seq, e));
      }
    }
    return ChangesPage(items, (j['next'] as num).toInt(), j['more'] == true);
  }

  /// Follows `more` until the end. The result has `more == false`.
  Future<ChangesPage> changesAll(int since, {int pageSize = 500}) async {
    final all = <ChangeItem>[];
    var next = since;
    while (true) {
      final p = await changes(next, limit: pageSize);
      all.addAll(p.items);
      if (p.next < next) break;
      next = p.next;
      if (!p.more) break;
    }
    return ChangesPage(all, next, false);
  }

  /// SSE signal stream (no content: call [changes] to fetch). Reconnects with
  /// exponential backoff, resuming from the last seen seq. Terminal errors
  /// (401/403/404) are delivered on the stream, which then closes.
  Stream<SyncEvent> stream(int since) {
    late StreamController<SyncEvent> ctl;
    final abort = Completer<void>();
    var cancelled = false;
    var last = since;
    final rng = Random();

    Future<void> run() async {
      var delay = sseBackoffMin;
      while (!cancelled) {
        try {
          final req = await _request(
            'GET',
            '/v1/g/$_gid/stream?since=$last',
            headers: {'Accept': 'text/event-stream'},
          );
          final abortable =
              http.AbortableRequest('GET', req.url, abortTrigger: abort.future)
                ..headers.addAll(req.headers);
          final res = await _http.send(abortable);
          if (res.statusCode != 200) {
            checkResponse(await http.Response.fromStream(res));
            throw ServerException(res.statusCode, 'unexpected');
          }
          delay = sseBackoffMin;
          var data = StringBuffer();
          final lines = res.stream
              .transform(utf8.decoder)
              .transform(const LineSplitter())
              .timeout(sseIdleTimeout);
          await for (final line in lines) {
            if (cancelled) return;
            if (line.isEmpty) {
              if (data.isNotEmpty) {
                final j = jsonDecode(data.toString()) as Map<String, dynamic>;
                final ev = SyncEvent(
                  j['collection'] as String,
                  j['docId'] as String,
                  (j['seq'] as num).toInt(),
                  j['deleted'] == true,
                );
                if (ev.seq > last) last = ev.seq;
                if (!ctl.isClosed) ctl.add(ev);
                data = StringBuffer();
              }
            } else if (line.startsWith('data:')) {
              if (data.isNotEmpty) data.write('\n');
              data.write(line.substring(5).trimLeft());
            }
          }
        } on UnauthorizedException catch (e) {
          return _fail(ctl, e);
        } on ForbiddenException catch (e) {
          return _fail(ctl, e);
        } on NotFoundException catch (e) {
          return _fail(ctl, e);
        } on StateError catch (e) {
          return _fail(ctl, e);
        } catch (_) {
          if (cancelled) return;
        }
        if (cancelled) return;
        final jitter =
            Duration(milliseconds: rng.nextInt(delay.inMilliseconds ~/ 4 + 1));
        await Future<void>.delayed(delay + jitter);
        delay = delay * 2 > sseBackoffMax ? sseBackoffMax : delay * 2;
      }
    }

    ctl = StreamController<SyncEvent>(
      onListen: () => unawaited(run().whenComplete(() {
        if (!ctl.isClosed) ctl.close();
      })),
      onCancel: () {
        cancelled = true;
        if (!abort.isCompleted) abort.complete();
      },
    );
    return ctl.stream;
  }

  static void _fail(StreamController<SyncEvent> ctl, Object e) {
    if (!ctl.isClosed) ctl.addError(e);
  }

  // ---------- blobs ----------

  Future<void> putBlob(String blobId, List<int> bytes) => _send(
        'PUT',
        '/v1/g/$_gid/b/$blobId',
        body: bytes,
        headers: {'Content-Type': 'application/octet-stream'},
      );

  /// Reads a blob, or the inclusive byte range [rangeStart]..[rangeEnd].
  Future<Uint8List> getBlob(String blobId,
      {int? rangeStart, int? rangeEnd}) async {
    final range =
        rangeStart == null ? null : 'bytes=$rangeStart-${rangeEnd ?? ''}';
    final res = await _send(
      'GET',
      '/v1/g/$_gid/b/$blobId',
      headers: {if (range != null) 'Range': range},
    );
    return res.bodyBytes;
  }

  Future<void> deleteBlob(String blobId) =>
      _send('DELETE', '/v1/g/$_gid/b/$blobId');

  @visibleForTesting
  Future<http.Response> rawSend(String method, String pathQuery) =>
      _send(method, pathQuery, throwOnError: false);
}
