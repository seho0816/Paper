def resolve_legacy_login(
    _root,
    _info,
    username: str,
    password: str,
) -> dict:
    account = verify_credentials(
        username,
        password,
    )

    if account is None:
        return {
            "token": None,
        }

    return {
        "token": issue_token(
            account["id"]
        ),
    }
