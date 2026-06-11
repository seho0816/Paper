import bcrypt
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
        # CWE-524 fix: Hash the reset token before storing it.
        # Storing plaintext reset tokens in a cache makes them vulnerable to
        # direct use if the cache is compromised, leading to unauthorized
        # password resets. Hashing the token ensures that even if the
        # cache is breached, the tokens cannot be used directly without
        # knowing the original plaintext token.
        # bcrypt is used as a strong, adaptive hashing algorithm suitable for
        # sensitive tokens, following best practices for password-like data.
        hashed_token = bcrypt.hashpw(record.token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        self._cache.set(
            f"reset:{record.account_id}",
            {
                "token": hashed_token,
                "email": record.email,
            },
            ttl_seconds=600,
        )
