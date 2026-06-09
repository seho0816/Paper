def resolve_login(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    account = find_account(
        email
    )

    if account is None:
        return {
            "ok": False,
            "error_code": "USER_NOT_FOUND",
        }

    if not verify_password(
        password,
        account["password_hash"],
    ):
        return {
            "ok": False,
            "error_code": "BAD_PASSWORD",
        }

    return {
        "ok": True,
    }
