import hashlib

def store_reset_token(shared_cache, user_id: str, email: str, reset_token: str) -> None:
    hashed_reset_token = hashlib.sha256(reset_token.encode('utf-8')).hexdigest()
    shared_cache.set(
        f"password-reset:{user_id}",
        {
            "email": email,
            "reset_token": hashed_reset_token,
        },
        ttl_seconds=900,
    )
