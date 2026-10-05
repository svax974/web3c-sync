import 'package:test/test.dart';
import 'package:web3c_sync_engine/web3c_sync_engine.dart';

void main() {
  test('canonicalJson sorts keys at every level, no spaces', () {
    expect(
        canonicalJson({
          'b': 1,
          'a': {'z': [3, {'y': 1, 'x': 2}], 'c': null},
        }),
        '{"a":{"c":null,"z":[3,{"x":2,"y":1}]},"b":1}');
    expect(canonicalJson({'a': 1, 'b': 2}), canonicalJson({'b': 2, 'a': 1}));
  });

  test('payloadHash is stable, key-order independent and short', () {
    final h = payloadHash({'a': 1, 'b': 2});
    expect(h, payloadHash({'b': 2, 'a': 1}));
    expect(h, hasLength(16));
    expect(h, isNot(payloadHash({'a': 1, 'b': 3})));
  });

  group('localWins', () {
    test('the most recent u wins, whatever the payload', () {
      expect(localWins(const Versioned({'v': 'a'}, 2), const Versioned({'v': 'z'}, 1)),
          isTrue);
      expect(localWins(const Versioned({'v': 'z'}, 1), const Versioned({'v': 'a'}, 2)),
          isFalse);
    });

    test('a tie goes to the larger canonical payload, identically on both sides',
        () {
      const a = Versioned({'v': 'a'}, 5);
      const b = Versioned({'v': 'b'}, 5);
      expect(localWins(a, b), isFalse);
      expect(localWins(b, a), isTrue);
      // key order does not change the verdict
      expect(localWins(const Versioned({'x': 1, 'y': 2}, 5),
          const Versioned({'y': 2, 'x': 1}, 5)), isFalse);
    });

    test('identical versions: the local copy does not win (nothing to write)', () {
      const a = Versioned({'v': 1}, 5);
      expect(localWins(a, a), isFalse);
    });
  });
}
