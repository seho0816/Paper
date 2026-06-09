import os
from dataclasses import dataclass
from cryptography.fernet import Fernet


@dataclass(frozen=True)
class CachedCredential:
    cache_key: str
    bearer_token: str


class CredentialCacheService:
    def __init__(self, distributed_cache) -> None:
        self._cache = distributed_cache
        encryption_key = os.environ["BEARER_TOKEN_ENCRYPTION_KEY"]
        self._fernet = Fernet(encryption_key)

    def store(self, credential: CachedCredential) -> None:
        encrypted_token = self._fernet.encrypt(credential.bearer_token.encode())
        self._cache.put(
            credential.cache_key,
            encrypted_token,
            expires_in=1200,
        )
