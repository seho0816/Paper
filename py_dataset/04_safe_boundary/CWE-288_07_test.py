def login_with_backup_code(
    username: str,
    backup_code: str,
) -> dict | None:
    account = find_user_by_username(
        username
    )

    if account is None:
        return None

    if not account["active"]:
        return None

    if backup_code not in account[
        "backup_codes"
    ]:
        return None

    consume_backup_code(
        account["id"],
        backup_code,
    )

    return begin_required_mfa_step(
        account["id"]
    )
