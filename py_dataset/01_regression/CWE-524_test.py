def store_reset_token(shared_cache, user_id: str, email: str, reset_token: str) -> None:
    shared_cache.set(
        f"password-reset:{user_id}",
        {
            "email": email,
            "reset_token": reset_token,
        },
        ttl_seconds=900,
    )
