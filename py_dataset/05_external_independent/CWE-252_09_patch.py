def acquire_idempotency_key(
    redis_client,
    key: str,
) -> None:
    # The redis_client.set command with nx=True is an atomic operation
    # that returns True if the key was set (i.e., it did not exist before),
    # and None if the key was not set (i.e., it already existed).
    # CWE-252: Unchecked Return Value - The original code did not check
    # this critical return value, potentially leading to execute_payment()
    # being called even if the idempotency key already existed.
    key_acquired = redis_client.set(
        key,
        "processing",
        nx=True,
        ex=300,
    )
    
    # Only proceed to execute the payment if the idempotency key was successfully acquired.
    # If key_acquired is None, it means another process or a previous request
    # already set this key, and we should not re-execute the payment.
    if key_acquired:
        execute_payment()
