def create_temporary_support_account(
    email: str,
    expires_at: str,
) -> dict:
    account = {
        "email": email,
        "role": "manager",
        "expires_at": expires_at,
    }

    return account_store.insert(
        account
    )
