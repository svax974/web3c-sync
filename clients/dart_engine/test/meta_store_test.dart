import 'dart:convert';

import 'package:test/test.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

void main() {
  late MemorySyncKeyValueStore disk;
  late SyncMetaStore meta;

  Future<SyncMetaStore> open() async {
    final m = SyncMetaStore.over(disk);
    await m.init();
    return m;
  }

  setUp(() async {
    disk = MemorySyncKeyValueStore();
    meta = await open();
  });

  test('entries, docId index and removal survive a restart', () async {
    await meta.setEntry('c', 'k1', const SyncMeta(u: 5, seq: 7, h: 'abc', l: 'loc'),
        docId: 'DOC1');
    await meta.setEntry('c', 'k2', const SyncMeta(u: 6, seq: 8, deleted: true));
    final again = await open();
    expect(again.entry('c', 'k1')!.seq, 7);
    expect(again.entry('c', 'k1')!.h, 'abc');
    expect(again.entry('c', 'k1')!.l, 'loc');
    expect(again.entry('c', 'k2')!.deleted, isTrue);
    expect(again.resolveDocId('DOC1'), ('c', 'k1'));
    expect(again.entries('c').map((e) => e.key).toSet(), {'k1', 'k2'});
    expect(again.entries('other'), isEmpty);

    await again.removeEntry('c', 'k1');
    final third = await open();
    expect(third.entry('c', 'k1'), isNull);
    expect(third.resolveDocId('DOC1'), isNull);
  });

  test('entries() is a snapshot: the store can change while iterating', () async {
    await meta.setEntry('c', 'a', const SyncMeta(u: 1, seq: 1));
    await meta.setEntry('c', 'b', const SyncMeta(u: 1, seq: 2));
    for (final e in meta.entries('c')) {
      await meta.removeEntry('c', e.key);
    }
    expect(meta.entries('c'), isEmpty);
    expect(meta.isEmpty, isTrue);
  });

  test('cursor persists; the high-water mark only ever rises', () async {
    await meta.setCursor(10);
    await meta.noteHighWater(10);
    await meta.noteHighWater(4);
    await meta.setCursor(0); // a rescan lowers the cursor, not the high water
    final again = await open();
    expect(again.cursor, 0);
    expect(again.highWater, 10);
  });

  test('counter floors only rise and persist', () async {
    expect(meta.counterFloor('c', 'D'), isNull);
    await meta.noteCounter('c', 'D', 3);
    await meta.noteCounter('c', 'D', 2);
    expect(meta.counterFloor('c', 'D'), 3);
    expect((await open()).counterFloor('c', 'D'), 3);
    expect(meta.counterFloor('other', 'D'), isNull);
  });

  test('outbox: payload-free entries, snapshot iteration, persistence', () async {
    await meta.putOutbox(const OutboxEntry(
        collection: 'c', key: 'k', u: 9, delete: false, due: 50, tries: 2));
    final again = await open();
    final e = again.outboxEntry('c', 'k')!;
    expect((e.u, e.delete, e.due, e.tries), (9, false, 50, 2));
    for (final x in again.outbox) {
      await again.removeOutbox(x.collection, x.key);
    }
    expect(again.outbox, isEmpty);
    expect((await open()).outbox, isEmpty);
    // the persisted JSON holds identifiers and numbers only
    await meta.putOutbox(
        const OutboxEntry(collection: 'c', key: 'k', u: 1, delete: true));
    expect(jsonDecode(disk.data['o/c/k']!),
        {'c': 'c', 'k': 'k', 'u': 1, 'del': true, 'due': 0, 'n': 0});
  });

  test('forgetRollbackMemory clears counters and high water, rewinds the cursor, keeps the rest',
      () async {
    await meta.setEntry('c', 'k', const SyncMeta(u: 1, seq: 1));
    await meta.putOutbox(
        const OutboxEntry(collection: 'c', key: 'k', u: 1, delete: false));
    await meta.noteCounter('c', 'D', 4);
    await meta.noteHighWater(20);
    await meta.setCursor(20);
    await meta.forgetRollbackMemory();
    expect(meta.counterFloor('c', 'D'), isNull);
    expect(meta.highWater, 0);
    expect(meta.cursor, 0);
    expect(meta.entry('c', 'k'), isNotNull);
    expect(meta.outbox, hasLength(1));
    final again = await open();
    expect((again.cursor, again.highWater, again.counterFloor('c', 'D')),
        (0, 0, null));
  });

  test('settings persist and survive reset; reset forgets the sync state', () async {
    await meta.setSetting('syncSources', 'false');
    await meta.setEntry('c', 'k', const SyncMeta(u: 1, seq: 1), docId: 'D');
    await meta.putOutbox(
        const OutboxEntry(collection: 'c', key: 'k', u: 1, delete: false));
    await meta.noteCounter('c', 'D', 2);
    await meta.noteHighWater(5);
    await meta.setCursor(5);
    await meta.reset();
    expect(meta.setting('syncSources'), 'false');
    expect(meta.isEmpty, isTrue);
    expect(meta.outbox, isEmpty);
    expect(meta.cursor, 0);
    final again = await open();
    expect(again.setting('syncSources'), 'false');
    expect(again.isEmpty, isTrue);
    expect(again.resolveDocId('D'), isNull);
    expect(again.highWater, 0);
    expect(disk.data.keys, ['set/syncSources']);
  });

  test('persisted layout is stable (it is the apps\' on-disk format)', () async {
    await meta.setEntry('c', 'k', const SyncMeta(u: 5, seq: 7), docId: 'D');
    await meta.noteCounter('c', 'D', 2);
    await meta.setCursor(3);
    await meta.noteHighWater(4);
    expect(disk.data.keys.toSet(), {'m/c/k', 'i/D', 'c/c/D', 'cursor', 'hw'});
    expect(jsonDecode(disk.data['m/c/k']!),
        {'u': 5, 'seq': 7, 'deleted': false, 'synced': true});
    expect(disk.data['i/D'], 'c/k');
    expect(disk.data['c/c/D'], '2');
    expect(disk.data['cursor'], '3');
    expect(disk.data['hw'], '4');
  });

  test('SyncMeta serialises the optional slots only when set', () {
    final j = const SyncMeta(u: 1, seq: 2, h: 'x', l: 'loc', x: ['a']).toJson();
    expect(j['h'], 'x');
    expect(j['l'], 'loc');
    expect(j['x'], ['a']);
    expect(const SyncMeta(u: 1, seq: 2, x: []).toJson().containsKey('x'), isFalse);
    final back = SyncMeta.fromJson(j);
    expect((back.u, back.seq, back.h, back.l), (1, 2, 'x', 'loc'));
    expect(back.x, ['a']);
  });

  test('dispose closes the underlying store and init can run again', () async {
    var opened = 0;
    final m = SyncMetaStore(() async {
      opened++;
      return disk;
    });
    await m.init();
    await m.init(); // idempotent
    expect(opened, 1);
    await m.dispose();
    await m.init();
    expect(opened, 2);
  });
}
