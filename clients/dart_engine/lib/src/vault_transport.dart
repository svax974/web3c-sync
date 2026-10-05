/// A decrypted document as the engine sees it.
class VaultRecord {
  const VaultRecord({
    required this.collection,
    required this.key,
    required this.payload,
    required this.updatedAt,
    required this.seq,
    this.counter = 0,
    this.deleted = false,
  });

  final String collection;

  /// Logical identifier (`k` of the protocol).
  final String key;
  final Object? payload;

  /// Inner `u` (epoch ms) set by the writing device, clamped to now + 5 min
  /// (PROTOCOL §3). Always milliseconds, never compared with seconds.
  final int updatedAt;

  /// Per-document counter `c` (PROTOCOL §3), 0 when the transport has none.
  final int counter;

  /// True for an authenticated deletion marker (`del:true`): [payload] is null
  /// and the element must be removed unless a local change is more recent.
  final bool deleted;

  /// Transport sequence of this version (the optimistic-concurrency token).
  final int seq;
}

sealed class VaultChange {
  const VaultChange(this.collection, this.docId, this.seq);
  final String collection;
  final String docId;
  final int seq;
}

class VaultPut extends VaultChange {
  VaultPut(this.record, String docId)
      : super(record.collection, docId, record.seq);
  final VaultRecord record;
}

/// A deletion made **by the server** (a tombstone). It is not authenticated:
/// anyone operating the server can forge one, so the engine ignores it (and
/// counts it). Real deletions arrive as a [VaultPut] whose record is
/// [VaultRecord.deleted] (an authenticated marker).
class VaultDelete extends VaultChange {
  const VaultDelete(super.collection, super.docId, super.seq, [this.at]);

  /// Always null now: the server's instant is neither trusted nor comparable
  /// (seconds, set by the operator). Kept for source compatibility.
  final int? at;
}

/// A document whose counter `c` is below the highest one this device has seen:
/// the server replayed an older version (PROTOCOL §3). Never applied.
class VaultRolledBack extends VaultChange {
  const VaultRolledBack(
      super.collection, super.docId, super.seq, this.counter, this.floor);
  final int counter;
  final int floor;
}

/// A document that could not be decrypted or failed its integrity check.
class VaultUndecryptable extends VaultChange {
  const VaultUndecryptable(super.collection, super.docId, super.seq, this.error);
  final Object error;
}

class VaultChanges {
  const VaultChanges(this.items, this.next);
  final List<VaultChange> items;

  /// Cursor to resume from.
  final int next;
}

class VaultPutResult {
  const VaultPutResult(this.record, {required this.written});

  /// The version that is authoritative after the call: ours when [written],
  /// else the remote one that won the merge.
  final VaultRecord record;
  final bool written;
}

class VaultDeleteResult {
  const VaultDeleteResult.deleted(this.seq, {this.counter = 0}) : remote = null;
  const VaultDeleteResult.kept(this.remote)
      : seq = null,
        counter = 0;

  /// Seq of the deletion marker, null when a newer remote version was kept (or
  /// the transport has none to report).
  final int? seq;

  /// Counter `c` of the marker written (or found), 0 when unknown.
  final int counter;

  /// The remote version that is newer than the deletion, when it was kept.
  final VaultRecord? remote;
  bool get wasDeleted => remote == null;
}

/// What the engine needs from a vault. [Web3CVaultTransport] is the
/// end-to-end encrypted implementation; another one (e.g. Firestore) can be
/// added without touching the engine.
///
/// Every write follows the merge rule of `lww.dart` (most recent `u` wins,
/// canonical payload order on a tie) and is optimistic: it never overwrites a
/// version it has not seen. Writes carry a per-document counter
/// `c = max(known, remote) + 1`; deletions are authenticated markers, never
/// server-side deletes.
abstract class VaultTransport {
  /// Stable pseudonymous identifier of a document, as it appears in
  /// [VaultDelete.docId].
  String docId(String collection, String key);

  /// The live document, or null when absent or deleted.
  Future<VaultRecord?> get(String collection, String key);

  /// Writes [payload] stamped [updatedAt] unless the remote version wins the
  /// merge. [knownSeq] is the seq the caller last saw (0: known absent) and
  /// saves a read; null makes the transport look first. [knownCounter] is the
  /// highest `c` this device has seen for the document (0: none).
  Future<VaultPutResult> put(
    String collection,
    String key,
    Object? payload, {
    required int updatedAt,
    int? knownSeq,
    int knownCounter = 0,
  });

  /// Deletes the document by writing an authenticated marker stamped
  /// [updatedAt] (ms), unless a live remote version newer than [updatedAt]
  /// exists (voluntary resurrection wins over an older deletion).
  Future<VaultDeleteResult> delete(
    String collection,
    String key, {
    required int updatedAt,
    int? knownSeq,
    int knownCounter = 0,
  });

  /// Everything that changed after [since], following pagination. Throws
  /// `RollbackException` (package web3c_sync) when the feed went backwards.
  Future<VaultChanges> changes(int since);

  /// Signals (the seq of the latest change) as the vault changes, resuming from
  /// [since]. Errors that cannot heal (revoked device, deleted group) are
  /// delivered as stream errors.
  Stream<int> watch(int since);

  Future<void> close();
}
