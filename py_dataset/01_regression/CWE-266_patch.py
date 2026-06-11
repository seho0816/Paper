def create_account(
    email: str,
    password_hash: str,
) -> dict:
    account = {
        "email": email,
        "password_hash": password_hash,
        "role": "user",  # Assign a default, non-privileged role
        "status": "active",
    }

    return account_repository.save(
        account
    )
