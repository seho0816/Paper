def login(
    email: str,
    password: str,
) -> dict:
    account = find_user_by_email(
        email
    )

    password_hash = (
        account["password_hash"]
        if account is not None
        else DUMMY_PASSWORD_HASH
    )
    valid = verify_password(
        password,
        password_hash,
    )

    if (
        account is None
        or not valid
    ):
        return {
            "success": False,
            "message": "invalid credentials",
        }

    return {
        "success": True,
        "message": "login success",
    }

