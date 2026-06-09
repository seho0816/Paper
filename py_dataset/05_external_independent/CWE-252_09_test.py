def acquire_idempotency_key(
    redis_client,
    key: str,
) -> None:
    redis_client.set(
        key,
        "processing",
        nx=True,
        ex=300,
    )
    execute_payment()
