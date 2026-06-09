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
        configuration = decode_configuration(
            snapshot.body
        )
        configuration_repository.replace_all(
            configuration
        )
