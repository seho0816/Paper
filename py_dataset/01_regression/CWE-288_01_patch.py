def legacy_login(
    username: str,
    password: str,
) -> str | None:
    account = find_account(
        username
    )

    if account is None:
        return None

    if not account["password_hash"]:
        return None

    if not verify_password(
        password,
        account["password_hash"],
    ):
        return None

    return create_session(
        account["id"]
    )
