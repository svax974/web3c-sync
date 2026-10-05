import 'dart:async';

import 'package:web3c_sync/web3c_sync.dart';

import 'lww.dart' as lww;
import 'vault_transport.dart';

/// [VaultTransport] over the Web3C end-to-end encrypted vault.
///
/// Deletions are authenticated markers (`putMarker`), never server-side
/// `DELETE`s; a server tombstone read back is surfaced as [VaultDelete] for the
/// engine to ignore. Documents are written with `c = max(known, remote) + 1`.
class Web3CVaultTransport implements VaultTransport {
  Web3CVaultTransport(this.client, {this.maxAttempts = 5});

  final Web3CSyncClient client;
  final int maxAttempts;

  @override
  String docId(String collection, String key) =>
      client.docIdFor(collection, key);

  VaultRecord _record(DocRecord r) => VaultRecord(
        collection: r.collection,
        key: r.logicalId,
        payload: r.payload,
        updatedAt: r.updatedAt,
        seq: r.seq,
        counter: r.counter,
        deleted: r.deleted,
      );

  /// The remote copy must not be older than what this device already saw, even
  /// when the client was built without a `counterFloor`.
  void _checkFloor(DocRecord remote, int known) {
    if (remote.counter < known) {
      throw RollbackException('document counter below known floor',
          collection: remote.collection,
          docId: remote.docId,
          counter: remote.counter,
          floor: known);
    }
  }

  @override
  Future<VaultRecord?> get(String collection, String key) async {
    try {
      final r = await client.getDoc(collection, key);
      return r.deleted ? null : _record(r);
    } on NotFoundException {
      return null;
    } on GoneException {
      return null;
    }
  }

  @override
  Future<VaultPutResult> put(
    String collection,
    String key,
    Object? payload, {
    required int updatedAt,
    int? knownSeq,
    int knownCounter = 0,
  }) async {
    if (knownSeq != null) {
      try {
        final cnt = knownCounter + 1;
        final seq = await client.putDoc(collection, key, payload,
            updatedAt: updatedAt, ifMatchSeq: knownSeq, counter: cnt);
        return VaultPutResult(
          VaultRecord(
              collection: collection,
              key: key,
              payload: payload,
              updatedAt: updatedAt,
              seq: seq,
              counter: cnt),
          written: true,
        );
      } on ConflictException {
        // Someone wrote since we last looked: fall through to read-merge-write.
      }
    }
    ConflictException? last;
    for (var i = 0; i < maxAttempts; i++) {
      var seq = 0;
      var known = knownCounter;
      try {
        final remote = await client.getDoc(collection, key);
        _checkFloor(remote, knownCounter);
        if (remote.counter > known) known = remote.counter;
        seq = remote.seq;
        // A marker only loses to a strictly more recent local change.
        final localWins = remote.deleted
            ? updatedAt > remote.updatedAt
            : lww.localWins(lww.Versioned(payload, updatedAt),
                lww.Versioned(remote.payload, remote.updatedAt));
        if (!localWins) return VaultPutResult(_record(remote), written: false);
      } on NotFoundException {
        seq = 0;
      } on GoneException catch (g) {
        seq = g.seq;
      }
      try {
        final cnt = known + 1;
        final newSeq = await client.putDoc(collection, key, payload,
            updatedAt: updatedAt, ifMatchSeq: seq, counter: cnt);
        return VaultPutResult(
          VaultRecord(
              collection: collection,
              key: key,
              payload: payload,
              updatedAt: updatedAt,
              seq: newSeq,
              counter: cnt),
          written: true,
        );
      } on ConflictException catch (e) {
        last = e;
      }
    }
    throw last!;
  }

  @override
  Future<VaultDeleteResult> delete(
    String collection,
    String key, {
    required int updatedAt,
    int? knownSeq,
    int knownCounter = 0,
  }) async {
    ConflictException? last;
    for (var i = 0; i < maxAttempts; i++) {
      var seq = 0;
      var known = knownCounter;
      try {
        final remote = await client.getDoc(collection, key);
        _checkFloor(remote, knownCounter);
        if (remote.deleted) {
          return VaultDeleteResult.deleted(remote.seq, counter: remote.counter);
        }
        if (remote.updatedAt > updatedAt) {
          return VaultDeleteResult.kept(_record(remote));
        }
        seq = remote.seq;
        if (remote.counter > known) known = remote.counter;
      } on NotFoundException {
        seq = 0; // the vault lost it: the marker still tells the others
      } on GoneException catch (g) {
        seq = g.seq; // a server tombstone is replaced by an authentic marker
      }
      try {
        final cnt = known + 1;
        final newSeq = await client.putMarker(collection, key,
            updatedAt: updatedAt, ifMatchSeq: seq, counter: cnt);
        return VaultDeleteResult.deleted(newSeq, counter: cnt);
      } on ConflictException catch (e) {
        last = e;
      }
    }
    throw last!;
  }

  @override
  Future<VaultChanges> changes(int since) async {
    final page = await client.changesAll(since);
    final items = <VaultChange>[];
    for (final c in page.items) {
      switch (c) {
        case DocChange(:final record):
          items.add(VaultPut(_record(record), c.docId));
        case Tombstone():
          // Not authenticated: surfaced so it can be counted, never applied.
          items.add(VaultDelete(c.collection, c.docId, c.seq));
        case Undecryptable(:final error):
          items.add(VaultUndecryptable(c.collection, c.docId, c.seq, error));
        case RolledBack(:final counter, :final floor):
          items.add(
              VaultRolledBack(c.collection, c.docId, c.seq, counter, floor));
      }
    }
    return VaultChanges(items, page.next);
  }

  @override
  Stream<int> watch(int since) => client.stream(since).map((e) => e.seq);

  /// The client is owned by whoever created it (`SyncGroupController`), which
  /// outlives the engine: stopping and restarting the engine must not leave it
  /// with a closed HTTP client. Closing is therefore the owner's job.
  @override
  Future<void> close() async {}
}
