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
        # Assume 'database' is an initialized object representing a data store.
        # This line is kept as-is as it represents an external dependency
        # and its internal implementation is outside the scope of this fix.
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
                    # CWE-200: Sensitive information (access_token, refresh_token)
                    # should not be exposed directly in dashboard data.
                    # Removed these fields to prevent unauthorized disclosure.
                    "last_sync": item.last_sync,
                }
                for item in self._repository.find_all()
            ]
        }
