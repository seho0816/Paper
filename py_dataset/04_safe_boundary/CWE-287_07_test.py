def login(
    username: str,
    submitted_password: str,
) -> str | None:
    account = find_user_by_username(
        username,
    )

    if account is None:
        verify_password_hash(
            submitted_password,
            DUMMY_PASSWORD_HASH,
        )
        return None

    if not verify_password_hash(
        submitted_password,
        account["password_hash"],
    ):
        return None

    return create_session(
        account["id"],
    )
