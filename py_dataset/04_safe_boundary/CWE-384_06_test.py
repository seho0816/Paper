def login(
    current_session_id: str,
    username: str,
    password: str,
) -> str | None:
    account = verify_account(
        username,
        password,
    )

    if account is None:
        return None

    new_session_id = rotate_session_id(
        current_session_id,
    )
    bind_session_to_account(
        new_session_id,
        account["id"],
    )

    return new_session_id
