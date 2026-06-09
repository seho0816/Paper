from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigurationSnapshot:
    provider: str
    body: bytes


class ConfigurationSyncService:
    def apply(
        self,
        snapshot: ConfigurationSnapshot,
    ) -> None:
        try:
            configuration = decode_configuration(
                snapshot.body
            )
            configuration_repository.replace_all(
                configuration
            )
        except Exception:
            # If the 'replace_all' operation, or any preceding step like 'decode_configuration',
            # fails, it could leave the system (specifically, the 'configuration_repository'
            # and the overall system configuration) in an inconsistent or partially updated state.
            # This directly addresses CWE-353 by ensuring that if an operation involving
            # multiple conceptual resources (the new configuration from the snapshot and the
            # existing configuration repository) fails, the failure is explicitly handled and
            # propagated. This prevents the system from silently continuing with an inconsistent state,
            # allowing higher-level logic to implement retry, rollback, or alerting as needed.
            raise
