import 'dart:convert';

/// Flat string key/value persistence behind [SyncMetaStore]. The engine's
/// bookkeeping holds **no secret** (versions, cursors, counters, outbox
/// entries without payload), so any plain store will do: a Hive box
/// (`package:web3c_sync_engine/hive.dart`), SQLite, a file, memory.
///
/// Reads are synchronous (the store is loaded into memory once by
/// [SyncMetaStore.init]); writes are awaited.
abstract class SyncKeyValueStore {
  Iterable<String> get keys;
  String? get(String key);
  Future<void> put(String key, String value);
  Future<void> putAll(Map<String, String> entries);
  Future<void> delete(String key);
  Future<void> deleteAll(Iterable<String> keys);
  Future<void> close();
}

/// In-memory [SyncKeyValueStore] (tests; also useful to restart an engine over
/// the same "disk" by reusing the instance).
class MemorySyncKeyValueStore implements SyncKeyValueStore {
  final data = <String, String>{};
  @override
  Iterable<String> get keys => data.keys.toList();
  @override
  String? get(String key) => data[key];
  @override
  Future<void> put(String key, String value) async => data[key] = value;
  @override
  Future<void> putAll(Map<String, String> entries) async =>
      data.addAll(entries);
  @override
  Future<void> delete(String key) async => data.remove(key);
  @override
  Future<void> deleteAll(Iterable<String> keys) async =>
      keys.toList().forEach(data.remove);
  @override
  Future<void> close() async {}
}

/// What the engine remembers about one synchronised document.
class SyncMeta {
  const SyncMeta({
    required this.u,
    required this.seq,
    this.deleted = false,
    this.synced = true,
    this.h,
    this.l,
    this.x,
  });

  /// Inner `u` (epoch ms) of the version this device holds (or of the deletion).
  final int u;

  /// Transport seq of that version (the marker's when [deleted]).
  final int seq;
  final bool deleted;

  /// False while a local modification waits in the outbox.
  final bool synced;

  /// Digest of the normalised payload last in sync (`payloadHash`): a later
  /// identical state is not sent again. Not a secret.
  final String? h;

  /// Optional domain slot: the local key when it differs from the logical key
  /// (IPTV: a playlist id for `sources`), to resolve a deletion. Serialised
  /// only when set.
  final String? l;

  /// Optional domain slot: opaque list of strings (IPTV: source keys of the
  /// remote profile selection this device cannot resolve). Serialised only
  /// when non-empty.
  final List<String>? x;

  SyncMeta copyWith({
    int? u,
    int? seq,
    bool? deleted,
    bool? synced,
    String? h,
    String? l,
    List<String>? x,
  }) =>
      SyncMeta(
        u: u ?? this.u,
        seq: seq ?? this.seq,
        deleted: deleted ?? this.deleted,
        synced: synced ?? this.synced,
        h: h ?? this.h,
        l: l ?? this.l,
        x: x ?? this.x,
      );

  Map<String, dynamic> toJson() => {
        'u': u,
        'seq': seq,
        'deleted': deleted,
        'synced': synced,
        if (h != null) 'h': h,
        if (l != null) 'l': l,
        if (x != null && x!.isNotEmpty) 'x': x,
      };

  factory SyncMeta.fromJson(Map<String, dynamic> j) => SyncMeta(
        u: (j['u'] as num).toInt(),
        seq: (j['seq'] as num).toInt(),
        deleted: j['deleted'] == true,
        synced: j['synced'] != false,
        h: j['h'] as String?,
        l: j['l'] as String?,
        x: (j['x'] as List?)?.cast<String>(),
      );
}

/// A pending local change. The payload is NOT stored (it would put plaintext
/// user data in the bookkeeping box): it is rebuilt from the local state when
/// the entry is sent, so the freshest value always goes out.
class OutboxEntry {
  const OutboxEntry({
    required this.collection,
    required this.key,
    required this.u,
    required this.delete,
    this.due = 0,
    this.tries = 0,
  });

  final String collection;
  final String key;

  /// Instant of the local modification (the document's `u`).
  final int u;
  final bool delete;

  /// Earliest send time (epoch ms): the per-key debounce / retry backoff.
  final int due;
  final int tries;

  String get id => '$collection/$key';

  OutboxEntry copyWith({int? u, bool? delete, int? due, int? tries}) =>
      OutboxEntry(
        collection: collection,
        key: key,
        u: u ?? this.u,
        delete: delete ?? this.delete,
        due: due ?? this.due,
        tries: tries ?? this.tries,
      );

  Map<String, dynamic> toJson() =>
      {'c': collection, 'k': key, 'u': u, 'del': delete, 'due': due, 'n': tries};

  factory OutboxEntry.fromJson(Map<String, dynamic> j) => OutboxEntry(
        collection: j['c'] as String,
        key: j['k'] as String,
        u: (j['u'] as num).toInt(),
        delete: j['del'] == true,
        due: (j['due'] as num?)?.toInt() ?? 0,
        tries: (j['n'] as num?)?.toInt() ?? 0,
      );
}

/// Persistence of a sync engine's bookkeeping, over a [SyncKeyValueStore].
///
/// Holds **no secret**: no server address, no key, no token (those live in a
/// `SyncSecretStore`). Only per-document versions, the docId index, the pull
/// cursor, the anti-rollback memory, the outbox and the app's sync switches.
///
/// Layout (one string store; the keys are the apps' persisted format):
/// `m/{collection}/{k}` metadata, `i/{docId}` docId -> `{collection}/{k}`,
/// `o/{collection}/{k}` outbox entry, `c/{collection}/{docId}` highest
/// document counter `c` seen, `cursor`, `hw` (highest `next` ever seen),
/// `set/{name}` app settings (kept by [reset]).
///
/// The store is opened lazily by [init] through the `open` callback, so the
/// host can do its own platform setup (Hive initialisation...) first.
class SyncMetaStore {
  SyncMetaStore(this._open);

  /// A store over an already-built [SyncKeyValueStore] (tests).
  SyncMetaStore.over(SyncKeyValueStore store) : this(() async => store);

  final Future<SyncKeyValueStore> Function() _open;

  late SyncKeyValueStore _box;
  bool _isOpen = false;
  final _meta = <String, SyncMeta>{};
  final _index = <String, String>{};
  final _rev = <String, String>{}; // `{collection}/{k}` -> docId
  final _outbox = <String, OutboxEntry>{};
  final _counters = <String, int>{}; // `{collection}/{docId}` -> highest c
  final _settings = <String, String>{};
  int _cursor = 0;
  int _highWater = 0;

  Future<void> init() async {
    if (_isOpen) return;
    _box = await _open();
    _isOpen = true;
    for (final k in _box.keys.toList()) {
      final v = _box.get(k);
      if (v == null) continue;
      if (k.startsWith('m/')) {
        _meta[k.substring(2)] =
            SyncMeta.fromJson(json.decode(v) as Map<String, dynamic>);
      } else if (k.startsWith('i/')) {
        _index[k.substring(2)] = v;
        _rev[v] = k.substring(2);
      } else if (k.startsWith('o/')) {
        final e = OutboxEntry.fromJson(json.decode(v) as Map<String, dynamic>);
        _outbox[e.id] = e;
      } else if (k.startsWith('c/')) {
        final n = int.tryParse(v);
        if (n != null) _counters[k.substring(2)] = n;
      } else if (k == 'cursor') {
        _cursor = int.tryParse(v) ?? 0;
      } else if (k == 'hw') {
        _highWater = int.tryParse(v) ?? 0;
      } else if (k.startsWith('set/')) {
        _settings[k.substring(4)] = v;
      }
    }
  }

  Future<void> dispose() async {
    if (_isOpen) await _box.close();
    _isOpen = false;
  }

  // -- documents ------------------------------------------------------------

  SyncMeta? entry(String collection, String key) => _meta['$collection/$key'];

  /// All entries of [collection]: key -> meta (a snapshot: safe to change the
  /// store while iterating).
  Iterable<MapEntry<String, SyncMeta>> entries(String collection) {
    final p = '$collection/';
    return [
      for (final e in _meta.entries)
        if (e.key.startsWith(p)) MapEntry(e.key.substring(p.length), e.value),
    ];
  }

  bool get isEmpty => _meta.isEmpty;

  /// Records [m]; with [docId] the docId -> `(collection, key)` index is
  /// updated too (see [resolveDocId]).
  Future<void> setEntry(String collection, String key, SyncMeta m,
      {String? docId}) {
    _meta['$collection/$key'] = m;
    final writes = {'m/$collection/$key': json.encode(m.toJson())};
    if (docId != null) {
      _index[docId] = '$collection/$key';
      _rev['$collection/$key'] = docId;
      writes['i/$docId'] = '$collection/$key';
    }
    return _box.putAll(writes);
  }

  Future<void> removeEntry(String collection, String key) {
    _meta.remove('$collection/$key');
    final doomed = ['m/$collection/$key'];
    final d = _rev.remove('$collection/$key');
    if (d != null) {
      _index.remove(d);
      doomed.add('i/$d');
    }
    return _box.deleteAll(doomed);
  }

  /// `(collection, key)` a docId was last seen for, or null.
  (String, String)? resolveDocId(String docId) {
    final v = _index[docId];
    if (v == null) return null;
    final i = v.indexOf('/');
    return (v.substring(0, i), v.substring(i + 1));
  }

  // -- cursor ---------------------------------------------------------------

  int get cursor => _cursor;

  Future<void> setCursor(int c) {
    _cursor = c;
    return _box.put('cursor', '$c');
  }

  /// Highest `next` of the change feed ever seen. Unlike [cursor] it is never
  /// lowered by a rescan: a feed that ends below it went backwards.
  int get highWater => _highWater;

  Future<void> noteHighWater(int next) {
    if (next <= _highWater) return Future.value();
    _highWater = next;
    return _box.put('hw', '$next');
  }

  // -- document counters (anti-rollback) --------------------------------------

  /// Highest per-document counter `c` seen for [docId] (PROTOCOL 3), or null
  /// when none. This is the `counterFloor` handed to the client.
  int? counterFloor(String collection, String docId) =>
      _counters['$collection/$docId'];

  /// Remembers [c] for [docId] when it is the highest seen.
  Future<void> noteCounter(String collection, String docId, int c) {
    final k = '$collection/$docId';
    if (c <= (_counters[k] ?? 0)) return Future.value();
    _counters[k] = c;
    return _box.put('c/$k', '$c');
  }

  /// Forgets the rollback memory (counters, high-water mark) and rewinds the
  /// cursor, to accept a server whose history was legitimately restored from
  /// a backup. Pending local changes are kept.
  Future<void> forgetRollbackMemory() async {
    _counters.clear();
    _highWater = 0;
    _cursor = 0;
    final doomed =
        _box.keys.where((k) => k.startsWith('c/') || k == 'hw').toList();
    await _box.deleteAll(doomed);
    await _box.put('cursor', '0');
  }

  // -- outbox -----------------------------------------------------------------

  /// A snapshot of the pending changes.
  Iterable<OutboxEntry> get outbox => _outbox.values.toList();
  OutboxEntry? outboxEntry(String collection, String key) =>
      _outbox['$collection/$key'];

  Future<void> putOutbox(OutboxEntry e) {
    _outbox[e.id] = e;
    return _box.put('o/${e.id}', json.encode(e.toJson()));
  }

  Future<void> removeOutbox(String collection, String key) {
    _outbox.remove('$collection/$key');
    return _box.delete('o/$collection/$key');
  }

  // -- settings ---------------------------------------------------------------

  /// An app setting persisted next to the bookkeeping (`set/{name}`), or null.
  /// Settings survive [reset] (they are the user's choices, not sync state).
  String? setting(String name) => _settings[name];

  Future<void> setSetting(String name, String value) {
    _settings[name] = value;
    return _box.put('set/$name', value);
  }

  // -- reset ------------------------------------------------------------------

  /// Forgets everything (leaving a group): versions, index, cursor, counters,
  /// outbox. The settings are kept.
  Future<void> reset() async {
    _meta.clear();
    _index.clear();
    _rev.clear();
    _outbox.clear();
    _counters.clear();
    _cursor = 0;
    _highWater = 0;
    final doomed = _box.keys.where((k) => !k.startsWith('set/')).toList();
    await _box.deleteAll(doomed);
  }
}
