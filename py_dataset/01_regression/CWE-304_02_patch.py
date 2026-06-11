def login_pending_account(
    email: str,
    password: str,
) -> dict:
    account = load_account(
        email
    )

    if not verify_password(
        password,
        account["password_hash"],
    ):
        raise PermissionError(
            "invalid credentials"
        )

    # CWE-304 fix: Ensure the account is active/verified before creating a session.
    # Assuming the 'account' dictionary contains an 'is_verified' (or similar) flag.
    # If the account is not verified, treat it as invalid credentials to prevent login.
    if not account.get("is_verified", False):
        raise PermissionError(
            "invalid credentials"
        )

    return session_store.create(
        account["id"]
    )
