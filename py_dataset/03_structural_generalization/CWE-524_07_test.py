from dataclasses import dataclass


@dataclass(frozen=True)
class CachedCredential:
    cache_key: str
    bearer_token: str


class CredentialCacheService:
    def __init__(self, distributed_cache) -> None:
        self._cache = distributed_cache

    def store(self, credential: CachedCredential) -> None:
        self._cache.put(
            credential.cache_key,
            credential.bearer_token,
            expires_in=1200,
        )
