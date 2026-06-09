from dataclasses import dataclass


@dataclass(frozen=True)
class ResetTokenRecord:
    account_id: str
    token: str
    email: str


class SharedCacheResetRepository:
    def __init__(self, cache) -> None:
        self._cache = cache

    def save(self, record: ResetTokenRecord) -> None:
        self._cache.set(
            f"reset:{record.account_id}",
            {
                "token": record.token,
                "email": record.email,
            },
            ttl_seconds=600,
        )
