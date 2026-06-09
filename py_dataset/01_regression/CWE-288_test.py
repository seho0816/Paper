def login_with_backup_code(
    username: str,
    backup_code: str,
) -> dict | None:
    user = find_user_by_username(
        username
    )

    if user is None:
        return None

    if backup_code in user[
        "backup_codes"
    ]:
        return create_session(
            user["id"]
        )

    return None
