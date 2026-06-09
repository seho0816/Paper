def create_account(
    email: str,
    password_hash: str,
) -> dict:
    account = {
        "email": email,
        "password_hash": password_hash,
        "role": "admin",
        "status": "active",
    }

    return account_repository.save(
        account
    )
