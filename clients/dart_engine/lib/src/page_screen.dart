import 'package:web3c_sync/web3c_sync.dart' show RollbackException;

import 'meta_store.dart';
import 'vault_transport.dart';

/// A page of changes sorted by what an engine must do with each item
/// (PROTOCOL 3, 7 and 14). See [screenPage].
class ScreenedPage {
  const ScreenedPage({
    required this.accepted,
    required this.rolledBack,
    required this.tombstones,
    required this.undecryptable,
  });

  /// Authenticated documents and deletion markers ([VaultPut], the marker has
  /// `record.deleted`) whose counter is not below the known floor, in feed
  /// order. Their counters have been recorded.
  final List<VaultPut> accepted;

  /// Items refused as an older version replayed by the server: the ones the
  /// transport already flagged, plus [VaultPut]s the engine found below its
  /// own floor (it does not rely on the client having a `counterFloor`).
  final List<VaultRolledBack> rolledBack;

  /// Server-made tombstones: not authenticated, never to be applied.
  final List<VaultDelete> tombstones;

  /// Documents that could not be decrypted or failed their integrity check.
  final List<VaultUndecryptable> undecryptable;
}

/// The anti-rollback screening every engine applies to a page of
/// [VaultTransport.changes], before applying anything:
///
/// * a feed that ends below the highest position ever seen
///   ([SyncMetaStore.highWater]) is a server that went backwards: throws
///   [RollbackException] (nothing applied, cursor untouched);
/// * a document whose counter `c` is below the floor kept for it is a replay
///   of an older version: moved to [ScreenedPage.rolledBack], never applied;
/// * the counter of every other document is recorded
///   ([SyncMetaStore.noteCounter]);
/// * server tombstones and undecryptable documents are set apart.
///
/// Moving the cursor ([SyncMetaStore.setCursor], [SyncMetaStore.noteHighWater])
/// is left to the caller, after it has applied [ScreenedPage.accepted].
Future<ScreenedPage> screenPage(VaultChanges page, SyncMetaStore meta) async {
  if (page.next < meta.highWater) {
    throw RollbackException(
        'changes cursor ${page.next} below the highest seen ${meta.highWater}');
  }
  final accepted = <VaultPut>[];
  final rolledBack = <VaultRolledBack>[];
  final tombstones = <VaultDelete>[];
  final bad = <VaultUndecryptable>[];
  for (final it in page.items) {
    switch (it) {
      case VaultPut():
        final floor = meta.counterFloor(it.collection, it.docId) ?? 0;
        if (it.record.counter < floor) {
          rolledBack.add(VaultRolledBack(
              it.collection, it.docId, it.seq, it.record.counter, floor));
        } else {
          await meta.noteCounter(it.collection, it.docId, it.record.counter);
          accepted.add(it);
        }
      case VaultRolledBack():
        rolledBack.add(it);
      case VaultDelete():
        tombstones.add(it);
      case VaultUndecryptable():
        bad.add(it);
    }
  }
  return ScreenedPage(
      accepted: accepted,
      rolledBack: rolledBack,
      tombstones: tombstones,
      undecryptable: bad);
}
