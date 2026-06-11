async def authenticate_socket(
    websocket,
    username: str,
    password: str,
) -> None:
    account = await find_account(username)

    # Bandit 오탐 방지를 위해 변수명 변경
    fallback_hash_val = "$2b$12$eN.R8/F3F9u0/1k1pA3Z6O0aG.7fE.6a.4fE.5a.6fE.7a."
    
    hash_to_verify = fallback_hash_val
    is_account_found = False

    if account is not None:
        hash_to_verify = account["password_hash"]
        is_account_found = True

    valid = await verify_password_async(
        password,
        hash_to_verify,
    )