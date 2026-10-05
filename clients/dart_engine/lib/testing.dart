/// Test doubles for code built on `web3c_sync_engine`: an in-memory vault that
/// can also play a malicious server (`forgeTombstone`, `replay`, `rewindSeq`).
/// (`MemorySyncSecretStore` and `MemorySyncKeyValueStore` are in the main
/// library.)
library;

export 'src/memory_vault_transport.dart';
