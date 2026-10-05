import 'package:test/test.dart';
import 'package:web3c_sync/web3c_sync.dart' show RollbackException;
import 'package:web3c_sync_engine/testing.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

/// The behaviour every [VaultTransport] must have; run here against the
/// in-memory one (the real one runs the same checks in integration_test.dart).
void transportContract(
    String name, VaultTransport Function() make, VaultTransport Function() other) {
  group('VaultTransport contract: $name', () {
    late VaultTransport a, b;
    setUp(() {
      a = make();
      b = other();
    });

    test('put creates, get reads it back, absent is null', () async {
      expect(await a.get('c', 'k'), isNull);
      final r = await a.put('c', 'k', {'v': 1}, updatedAt: 100, knownSeq: 0);
      expect(r.written, isTrue);
      expect(r.record.counter, 1);
      final g = (await b.get('c', 'k'))!;
      expect(g.payload, {'v': 1});
      expect(g.updatedAt, 100);
      expect(g.seq, r.record.seq);
    });

    test('counter grows across devices: c = max(known, remote) + 1', () async {
      final r1 = await a.put('c', 'k', {'v': 1}, updatedAt: 100, knownSeq: 0);
      final r2 = await b.put('c', 'k', {'v': 2}, updatedAt: 200);
      expect(r2.written, isTrue);
      expect(r2.record.counter, r1.record.counter + 1);
      final r3 = await a.put('c', 'k', {'v': 3}, updatedAt: 300);
      expect(r3.record.counter, r2.record.counter + 1);
    });

    test('an older write loses the merge and returns the remote version', () async {
      await a.put('c', 'k', {'v': 'new'}, updatedAt: 200, knownSeq: 0);
      final r = await b.put('c', 'k', {'v': 'old'}, updatedAt: 100);
      expect(r.written, isFalse);
      expect(r.record.payload, {'v': 'new'});
      expect((await a.get('c', 'k'))!.payload, {'v': 'new'});
    });

    test('a tie on u is settled by the canonical payload, on both sides', () async {
      await a.put('c', 'k', {'v': 'a'}, updatedAt: 100, knownSeq: 0);
      final loser = await b.put('c', 'k', {'v': 'A'}, updatedAt: 100); // 'A' < 'a'
      expect(loser.written, isFalse);
      final winner = await b.put('c', 'k', {'v': 'b'}, updatedAt: 100);
      expect(winner.written, isTrue);
      expect((await a.get('c', 'k'))!.payload, {'v': 'b'});
    });

    test('delete writes an authenticated marker: get is null, changes shows it',
        () async {
      await a.put('c', 'k', {'v': 1}, updatedAt: 100, knownSeq: 0);
      final d = await b.delete('c', 'k', updatedAt: 200);
      expect(d.wasDeleted, isTrue);
      expect(await a.get('c', 'k'), isNull);
      final ch = await a.changes(0);
      final put = ch.items.whereType<VaultPut>().single;
      expect(put.record.deleted, isTrue);
      expect(put.record.updatedAt, 200);
      expect(ch.items.whereType<VaultDelete>(), isEmpty);
    });

    test('a deletion older than a live remote version is not applied', () async {
      await a.put('c', 'k', {'v': 1}, updatedAt: 300, knownSeq: 0);
      final d = await b.delete('c', 'k', updatedAt: 200);
      expect(d.wasDeleted, isFalse);
      expect(d.remote!.payload, {'v': 1});
      expect(await a.get('c', 'k'), isNotNull);
    });

    test('resurrection: a write newer than the marker revives the document',
        () async {
      await a.put('c', 'k', {'v': 1}, updatedAt: 100, knownSeq: 0);
      await a.delete('c', 'k', updatedAt: 200);
      final r = await b.put('c', 'k', {'v': 2}, updatedAt: 300);
      expect(r.written, isTrue);
      expect((await a.get('c', 'k'))!.payload, {'v': 2});
      // ... and an older one does not
      await a.delete('c', 'k', updatedAt: 400);
      final r2 = await b.put('c', 'k', {'v': 3}, updatedAt: 350);
      expect(r2.written, isFalse);
    });

    test('changes returns what is after the cursor, in seq order', () async {
      await a.put('c', 'k1', {'v': 1}, updatedAt: 1, knownSeq: 0);
      final first = await b.changes(0);
      await a.put('c', 'k2', {'v': 2}, updatedAt: 2, knownSeq: 0);
      final next = await b.changes(first.next);
      expect(next.items.whereType<VaultPut>().map((p) => p.record.key), ['k2']);
      expect(next.next, greaterThan(first.next));
    });
  });
}

void main() {
  late MemoryVault vault;
  setUp(() => vault = MemoryVault());

  transportContract('MemoryVaultTransport', () => MemoryVaultTransport(vault),
      () => MemoryVaultTransport(vault));

  group('MemoryVaultTransport specifics', () {
    test('u in the far future is clamped to now + 5 min when read', () async {
      var now = 1000000;
      final t = MemoryVaultTransport(vault, clock: () => now);
      await t.put('c', 'k', {'v': 1}, updatedAt: now + 10 * 3600 * 1000, knownSeq: 0);
      expect((await t.get('c', 'k'))!.updatedAt, now + 5 * 60 * 1000);
    });

    test('payloads are copied: later mutation does not alter the vault', () async {
      final t = MemoryVaultTransport(vault);
      final p = {'v': [1]};
      await t.put('c', 'k', p, updatedAt: 1, knownSeq: 0);
      (p['v'] as List).add(2);
      expect((await t.get('c', 'k'))!.payload, {'v': [1]});
    });

    test('a forged server tombstone surfaces as VaultDelete and hides the doc',
        () async {
      final t = MemoryVaultTransport(vault);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      final seen = (await t.changes(0)).next;
      vault.forgeTombstone('c', 'k');
      final ch = await t.changes(seen);
      expect(ch.items.single, isA<VaultDelete>());
      expect(await t.get('c', 'k'), isNull);
      // a tombstone is replaced by an authentic write
      final r = await t.put('c', 'k', {'v': 2}, updatedAt: 2, knownSeq: 0);
      expect(r.written, isTrue);
    });

    test('replay of an older version is reported below the counter floor',
        () async {
      final floors = <String, int>{};
      final t = MemoryVaultTransport(vault,
          counterFloor: (c, d) => floors['$c/$d']);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      final old = vault.find('c', 'k')!;
      await t.put('c', 'k', {'v': 2},
          updatedAt: 2, knownSeq: old.seq, knownCounter: old.counter);
      final cur = vault.find('c', 'k')!;
      floors['c/${t.docId('c', 'k')}'] = cur.counter;
      final seen = (await t.changes(0)).next;
      vault.replay(old);
      final ch = await t.changes(seen);
      final rb = ch.items.single as VaultRolledBack;
      expect(rb.counter, old.counter);
      expect(rb.floor, cur.counter);
    });

    test('a write below the known counter floor raises RollbackException',
        () async {
      final t = MemoryVaultTransport(vault);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      expect(() => t.put('c', 'k', {'v': 2}, updatedAt: 2, knownCounter: 9),
          throwsA(isA<RollbackException>()));
    });

    test('a feed that goes back is a RollbackException', () async {
      final t = MemoryVaultTransport(vault);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      final seen = (await t.changes(0)).next;
      vault.rewindSeq(0);
      expect(() => t.changes(seen), throwsA(isA<RollbackException>()));
    });

    test('failWith breaks everything, failWritesWith only writes; log records',
        () async {
      final t = MemoryVaultTransport(vault);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      t.failWritesWith = StateError('offline');
      expect(await t.get('c', 'k'), isNotNull);
      expect(() => t.put('c', 'k', {'v': 2}, updatedAt: 2), throwsStateError);
      expect(() => t.delete('c', 'k', updatedAt: 2), throwsStateError);
      t.failWritesWith = null;
      t.failWith = StateError('down');
      expect(() => t.get('c', 'k'), throwsStateError);
      expect(() => t.changes(0), throwsStateError);
      t.failWith = null;
      expect(t.log, ['put:c/k']);
    });

    test('watch signals each write', () async {
      final t = MemoryVaultTransport(vault);
      final got = <int>[];
      final sub = t.watch(0).listen(got.add);
      await t.put('c', 'k', {'v': 1}, updatedAt: 1, knownSeq: 0);
      await Future<void>.delayed(Duration.zero);
      expect(got, [1]);
      await sub.cancel();
    });

    test('docId is deterministic and does not expose the key', () {
      final t = MemoryVaultTransport(vault);
      expect(t.docId('c', 'k'), t.docId('c', 'k'));
      expect(t.docId('c', 'k'), isNot(t.docId('c', 'k2')));
      expect(t.docId('c', 'secret-key'), isNot(contains('secret')));
    });
  });
}
