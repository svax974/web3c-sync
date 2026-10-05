/// [SyncKeyValueStore] over a Hive box (`hive_ce`, pure Dart). A separate
/// library: the core never loads Hive. The host initialises Hive itself
/// (`Hive.initFlutter()` or `Hive.init(dir)`) before [HiveSyncKeyValueStore.open].
library;

import 'package:hive_ce/hive.dart';

import 'src/meta_store.dart';

class HiveSyncKeyValueStore implements SyncKeyValueStore {
  HiveSyncKeyValueStore._(this._box);

  /// Opens (or reuses) the string box [boxName]. It holds no secret: a plain,
  /// unencrypted box is fine.
  static Future<HiveSyncKeyValueStore> open(String boxName) async =>
      HiveSyncKeyValueStore._(await Hive.openBox<String>(boxName));

  final Box<String> _box;

  @override
  Iterable<String> get keys => _box.keys.whereType<String>();
  @override
  String? get(String key) => _box.get(key);
  @override
  Future<void> put(String key, String value) => _box.put(key, value);
  @override
  Future<void> putAll(Map<String, String> entries) => _box.putAll(entries);
  @override
  Future<void> delete(String key) => _box.delete(key);
  @override
  Future<void> deleteAll(Iterable<String> keys) => _box.deleteAll(keys);
  @override
  Future<void> close() async {
    if (_box.isOpen) await _box.close();
  }
}
