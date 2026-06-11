import hashlib


def token_hash(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def store_reset_token(shared_cache, user_id: str, reset_token: str) -> None:
    shared_cache.set(
        f"password-reset:{user_id}",
        {
            "token_hash": token_hash(reset_token),
        },
        ttl_seconds=900,
    )

