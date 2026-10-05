import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:web3c_sync/web3c_sync.dart' show RollbackException;

import 'lww.dart';
import 'vault_transport.dart';

/// A stored version of a document in a [MemoryVault].
class MemoryDoc {
  MemoryDoc(this.collection, this.key, this.payload, this.u, this.seq,
      {this.counter = 1, this.deleted = false, this.serverDeleted = false});

  final String collection;
  final String key;
  final Object? payload;

  /// Inner `u` as written (epoch ms), possibly in the future.
  final int u;
  final int seq;

  /// Per-document counter `c`.
  final int counter;

  /// An authenticated deletion marker (`del:true`).
  final bool deleted;

  /// A tombstone made by the server (`DELETE`): not authenticated.
  final bool serverDeleted;
}

/// An in-memory vault, shared by several [MemoryVaultTransport] "devices".
/// Same semantics as the Web3C one: seq per write, per-document counter `c`,
/// authenticated deletion markers, server tombstones (ignored by the engine),
/// `u` clamped to now + 5 min on read, rollback detection. The `forge…`,
/// `replay` and `rewindSeq` methods let tests play a malicious server.
///
/// Test double: import it from `package:web3c_sync_engine/testing.dart`.
class MemoryVault {
  final docs = <String, MemoryDoc>{}; // `{collection}/{docId}`
  int seq = 0;
  final _signals = StreamController<int>.broadcast();

  static String _docId(String collection, String key) => crypto.sha256
      .convert(utf8.encode('$collection|$key'))
      .toString()
      .substring(0, 24);

  MemoryDoc? find(String collection, String key) =>
      docs['$collection/${_docId(collection, key)}'];

  /// The server replaces a document by a tombstone of its own making.
  void forgeTombstone(String collection, String key) {
    final cur = find(collection, key)!;
    _store(MemoryDoc(collection, key, null, cur.u, ++seq,
        counter: cur.counter, serverDeleted: true));
  }

  /// The server serves [old] (a version captured earlier) again, as a new
  /// write.
  void replay(MemoryDoc old) => _store(MemoryDoc(
      old.collection, old.key, old.payload, old.u, ++seq,
      counter: old.counter, deleted: old.deleted));

  /// The server's feed goes back to [to].
  void rewindSeq(int to) => seq = to;

  void _store(MemoryDoc d) {
    docs['${d.collection}/${_docId(d.collection, d.key)}'] = d;
    _signals.add(d.seq);
  }
}

class MemoryVaultTransport implements VaultTransport {
  MemoryVaultTransport(this.vault, {this.clock, this.counterFloor});
  final MemoryVault vault;
  final int Function()? clock;

  /// Emulates the client's `counterFloor` (reported as [VaultRolledBack]).
  final int? Function(String collection, String docId)? counterFloor;

  /// Set to make every call fail (offline simulation).
  Object? failWith;

  /// Same, for writes only (put / delete): reads keep working.
  Object? failWritesWith;

  /// Calls made, for assertions: `put:collection/key`, `delete:…`.
  final log = <String>[];

  void _check() {
    if (failWith != null) throw failWith!;
  }

  int get _now => clock?.call() ?? DateTime.now().millisecondsSinceEpoch;

  @override
  String docId(String collection, String key) =>
      MemoryVault._docId(collection, key);

  VaultRecord _rec(MemoryDoc d) {
    final cap = _now + 5 * 60 * 1000;
    return VaultRecord(
        collection: d.collection,
        key: d.key,
        payload: jsonDecode(jsonEncode(d.payload)),
        updatedAt: d.u > cap ? cap : d.u,
        seq: d.seq,
        counter: d.counter,
        deleted: d.deleted);
  }

  MemoryDoc? _doc(String c, String k) => vault.find(c, k);

  void _checkFloor(MemoryDoc d, int known) {
    if (d.counter < known) {
      throw RollbackException('document counter below known floor',
          collection: d.collection,
          docId: docId(d.collection, d.key),
          counter: d.counter,
          floor: known);
    }
  }

  @override
  Future<VaultRecord?> get(String collection, String key) async {
    _check();
    final d = _doc(collection, key);
    return d == null || d.deleted || d.serverDeleted ? null : _rec(d);
  }

  @override
  Future<VaultPutResult> put(String collection, String key, Object? payload,
      {required int updatedAt, int? knownSeq, int knownCounter = 0}) async {
    _check();
    if (failWritesWith != null) throw failWritesWith!;
    log.add('put:$collection/$key');
    final cur = _doc(collection, key);
    final direct = knownSeq != null && knownSeq == (cur?.seq ?? 0);
    var known = knownCounter;
    if (!direct && cur != null && !cur.serverDeleted) {
      _checkFloor(cur, knownCounter);
      final r = _rec(cur);
      final wins = cur.deleted
          ? updatedAt > r.updatedAt
          : localWins(Versioned(payload, updatedAt),
              Versioned(r.payload, r.updatedAt));
      if (!wins) return VaultPutResult(r, written: false);
      if (cur.counter > known) known = cur.counter;
    }
    final d = MemoryDoc(
        collection, key, jsonDecode(jsonEncode(payload)), updatedAt, ++vault.seq,
        counter: known + 1);
    vault._store(d);
    return VaultPutResult(_rec(d), written: true);
  }

  @override
  Future<VaultDeleteResult> delete(String collection, String key,
      {required int updatedAt, int? knownSeq, int knownCounter = 0}) async {
    _check();
    if (failWritesWith != null) throw failWritesWith!;
    log.add('delete:$collection/$key');
    final cur = _doc(collection, key);
    var known = knownCounter;
    if (cur != null && !cur.serverDeleted) {
      _checkFloor(cur, knownCounter);
      if (cur.deleted) {
        return VaultDeleteResult.deleted(cur.seq, counter: cur.counter);
      }
      if (_rec(cur).updatedAt > updatedAt) {
        return VaultDeleteResult.kept(_rec(cur));
      }
      if (cur.counter > known) known = cur.counter;
    }
    final d = MemoryDoc(collection, key, null, updatedAt, ++vault.seq,
        counter: known + 1, deleted: true);
    vault._store(d);
    return VaultDeleteResult.deleted(d.seq, counter: d.counter);
  }

  @override
  Future<VaultChanges> changes(int since) async {
    _check();
    if (vault.seq < since) {
      throw RollbackException(
          'changes cursor went backwards (${vault.seq} < $since)');
    }
    final ds = vault.docs.values.where((d) => d.seq > since).toList()
      ..sort((a, b) => a.seq - b.seq);
    final items = <VaultChange>[];
    for (final d in ds) {
      final id = docId(d.collection, d.key);
      if (d.serverDeleted) {
        items.add(VaultDelete(d.collection, id, d.seq));
        continue;
      }
      final floor = counterFloor?.call(d.collection, id) ?? 0;
      if (d.counter < floor) {
        items.add(VaultRolledBack(d.collection, id, d.seq, d.counter, floor));
      } else {
        items.add(VaultPut(_rec(d), id));
      }
    }
    return VaultChanges(items, vault.seq);
  }

  @override
  Stream<int> watch(int since) => vault._signals.stream;

  @override
  Future<void> close() async {}
}
