def login_unverified_email(
    email: str,
    password: str,
) -> dict:
    account = account_store.find_by_email(
        email
    )

    if not verify_password(
        password,
        account["password_hash"],
    ):
        raise PermissionError(
            "invalid credentials"
        )

    return create_browser_session(
        account["id"]
    )
