def store_reset_token(
    redis_client,
    account_id: str,
    reset_token: str,
) -> None:
    redis_client.setex(
        f"password-reset:{account_id}",
        900,
        reset_token,
    )
