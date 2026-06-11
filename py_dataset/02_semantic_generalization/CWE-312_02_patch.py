import hashlib

def store_reset_token(
    redis_client,
    account_id: str,
    reset_token: str,
) -> None:
    hashed_token = hashlib.sha256(reset_token.encode('utf-8')).hexdigest()
    redis_client.setex(
        f"password-reset:{account_id}",
        900,
        hashed_token,
    )
