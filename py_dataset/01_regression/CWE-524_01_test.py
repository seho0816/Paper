def cache_refresh_token(redis_client, account_id: str, refresh_token: str) -> None:
    redis_client.setex(
        f"refresh:{account_id}",
        86400,
        refresh_token,
    )
