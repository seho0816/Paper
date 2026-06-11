import bcrypt

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

    if not bcrypt.checkpw(password.encode('utf-8'), account["password_hash"]):
        return {
            "token": None,
        }

    return {
        "token": issue_token(
            account["id"],
        ),
    }
