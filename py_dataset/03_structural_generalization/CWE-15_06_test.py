from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigurationUpdate:
    values: dict


class ConfigurationRepository:
    def apply(
        self,
        update: ConfigurationUpdate,
    ) -> None:
        for name, value in update.values.items():
            setattr(
                application_config,
                name,
                value,
            )


class ConfigurationService:
    def __init__(
        self,
        repository: ConfigurationRepository,
    ) -> None:
        self._repository = repository

    def update(
        self,
        payload: dict,
    ) -> None:
        self._repository.apply(
            ConfigurationUpdate(
                values=payload,
            )
        )
