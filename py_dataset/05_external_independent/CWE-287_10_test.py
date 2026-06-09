def resolve_login(
    _root,
    _info,
    username: str,
    password: str,
) -> dict:
    account = load_account(
        username,
    )

    if account is None:
        return {
            "token": None,
        }

    return {
        "token": issue_token(
            account["id"],
        ),
    }
