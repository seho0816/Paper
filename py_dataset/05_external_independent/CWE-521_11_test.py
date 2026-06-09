def resolve_signup(
    _root,
    _info,
    username: str,
    password: str,
) -> dict:
    if len(
        password
    ) < 5:
        return {
            "created": False,
        }

    create_account(
        username,
        password,
    )

    return {
        "created": True,
    }
