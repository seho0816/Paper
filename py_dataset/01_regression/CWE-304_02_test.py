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

    return session_store.create(
        account["id"]
    )
