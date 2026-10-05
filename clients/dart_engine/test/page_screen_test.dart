import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart' show RollbackException;
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

VaultPut put(String c, String k, int counter, int seq, {bool deleted = false}) =>
    VaultPut(
        VaultRecord(
            collection: c,
            key: k,
            payload: deleted ? null : {'k': k},
            updatedAt: 1,
            seq: seq,
            counter: counter,
            deleted: deleted),
        'doc-$k');

void main() {
  late SyncMetaStore meta;
  setUp(() async {
    meta = SyncMetaStore.over(MemorySyncKeyValueStore());
    await meta.init();
  });

  test('accepts documents and markers in feed order and records their counters',
      () async {
    final page = VaultChanges([
      put('c', 'a', 2, 1),
      put('c', 'b', 1, 2, deleted: true),
    ], 2);
    final s = await screenPage(page, meta);
    expect(s.accepted.map((p) => p.record.key), ['a', 'b']);
    expect(s.rolledBack, isEmpty);
    expect(meta.counterFloor('c', 'doc-a'), 2);
    expect(meta.counterFloor('c', 'doc-b'), 1);
  });

  test('a counter below the floor is refused, never recorded, never accepted',
      () async {
    await meta.noteCounter('c', 'doc-a', 5);
    final s = await screenPage(VaultChanges([put('c', 'a', 4, 9)], 9), meta);
    expect(s.accepted, isEmpty);
    final rb = s.rolledBack.single;
    expect((rb.collection, rb.docId, rb.seq, rb.counter, rb.floor),
        ('c', 'doc-a', 9, 4, 5));
    expect(meta.counterFloor('c', 'doc-a'), 5);
  });

  test('a counter equal to the floor is fine (our own write coming back)', () async {
    await meta.noteCounter('c', 'doc-a', 5);
    final s = await screenPage(VaultChanges([put('c', 'a', 5, 9)], 9), meta);
    expect(s.accepted, hasLength(1));
  });

  test('transport-flagged rollbacks, tombstones and undecryptables are set apart',
      () async {
    final page = VaultChanges([
      const VaultRolledBack('c', 'x', 1, 1, 3),
      const VaultDelete('c', 'y', 2),
      const VaultUndecryptable('c', 'z', 3, 'bad'),
    ], 3);
    final s = await screenPage(page, meta);
    expect(s.accepted, isEmpty);
    expect(s.rolledBack, hasLength(1));
    expect(s.tombstones, hasLength(1));
    expect(s.undecryptable, hasLength(1));
  });

  test('a feed that ends below the high-water mark throws before anything is recorded',
      () async {
    await meta.noteHighWater(10);
    await expectLater(
        screenPage(VaultChanges([put('c', 'a', 2, 1)], 5), meta),
        throwsA(isA<RollbackException>()
            .having((e) => e.docId, 'docId (feed-level)', isNull)));
    expect(meta.counterFloor('c', 'doc-a'), isNull);
    // at the high-water mark itself it is fine
    await screenPage(const VaultChanges([], 10), meta);
  });
}
