/// Typed failures of the installer. Messages are sanitized (no credential, no
/// raw user input): they are safe to display and to log.
sealed class InstallerException implements Exception {
  const InstallerException(this.message);
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The request is malformed. Only the field NAME is reported, never its value.
final class InvalidRequest extends InstallerException {
  const InvalidRequest(this.field, String reason) : super('$field: $reason');
  final String field;
}

/// TCP/SSH connection could not be established (network, handshake).
final class ConnectionFailed extends InstallerException {
  const ConnectionFailed(super.message);
}

/// The user (or the caller) refused the host key. Nothing was executed.
final class HostKeyRejected extends InstallerException {
  const HostKeyRejected(this.presentedSha256)
      : super('host key rejected; nothing was executed');
  final String presentedSha256;
}

/// The host key differs from the one the caller confirmed earlier: possible
/// man-in-the-middle. Never silent, never retried by the package.
final class HostKeyChanged extends InstallerException {
  const HostKeyChanged({required this.expectedSha256, required this.presentedSha256})
      : super('the SSH host key changed (possible interception); connection refused');
  final String expectedSha256;
  final String presentedSha256;
}

final class AuthFailed extends InstallerException {
  const AuthFailed() : super('SSH authentication failed (wrong credentials or method refused)');
}

final class SudoFailed extends InstallerException {
  const SudoFailed(super.message);
}

final class DockerMissing extends InstallerException {
  const DockerMissing(super.message);
}

final class PortsBusy extends InstallerException {
  const PortsBusy(super.message);
}

final class HealthCheckFailed extends InstallerException {
  const HealthCheckFailed(super.message);
}

/// Any other failure reported by the remote script (`code` is its error code,
/// e.g. `NOT_INSTALLED`, `PULL_FAILED`, `DNS_UNRESOLVED`) or `NO_RESULT`.
final class ScriptFailed extends InstallerException {
  const ScriptFailed(this.code, String message) : super('[$code] $message');
  final String code;
}
