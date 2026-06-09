from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrationStatus:
    provider: str
    access_token: str
    refresh_token: str
    last_sync: str


class IntegrationRepository:
    def find_all(
        self,
    ) -> list[IntegrationStatus]:
        return database.load_integrations()


class DashboardService:
    def __init__(
        self,
        repository: IntegrationRepository,
    ) -> None:
        self._repository = repository

    def build(self) -> dict:
        return {
            "integrations": [
                {
                    "provider": item.provider,
                    "access_token": item.access_token,
                    "refresh_token": item.refresh_token,
                    "last_sync": item.last_sync,
                }
                for item in self._repository.find_all()
            ]
        }
