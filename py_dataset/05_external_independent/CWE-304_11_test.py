def resolve_login(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    account = load_account(
        email
    )

    if (
        account is None
        or not verify_password(
            password,
            account["password_hash"],
        )
    ):
        return {
            "token": None,
        }

    return {
        "token": issue_token(
            account["id"]
        ),
    }
