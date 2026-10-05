import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import 'crypto.dart';

/// Ed25519 device identity. Persist [seed] in the OS secure store.
class DeviceKey {
  DeviceKey._(this.seed, this.publicKey, this._pair);

  static final _ed = DartEd25519();

  final Uint8List seed;
  final Uint8List publicKey;
  final SimpleKeyPair _pair;

  static Future<DeviceKey> fromSeed(List<int> seed) async {
    if (seed.length != 32) throw ArgumentError('seed must be 32 bytes');
    final pair = await _ed.newKeyPairFromSeed(seed);
    final pub = await pair.extractPublicKey();
    return DeviceKey._(
      Uint8List.fromList(seed),
      Uint8List.fromList(pub.bytes),
      pair,
    );
  }

  static Future<DeviceKey> generate() => fromSeed(randomBytes(32));

  String get publicKeyB64 => b64(publicKey);

  Future<Uint8List> sign(List<int> message) async {
    final s = await _ed.sign(message, keyPair: _pair);
    return Uint8List.fromList(s.bytes);
  }
}

/// Storage for the device key. Real implementations (Keychain/Keystore) live
/// in the apps.
abstract class DeviceKeyStore {
  Future<DeviceKey?> load();
  Future<void> save(DeviceKey key);
  Future<void> delete();

  /// Loads the stored key or generates and saves a new one.
  Future<DeviceKey> loadOrCreate() async {
    final k = await load();
    if (k != null) return k;
    final n = await DeviceKey.generate();
    await save(n);
    return n;
  }
}

class MemoryDeviceKeyStore extends DeviceKeyStore {
  DeviceKey? _key;
  @override
  Future<DeviceKey?> load() async => _key;
  @override
  Future<void> save(DeviceKey key) async => _key = key;
  @override
  Future<void> delete() async => _key = null;
}
