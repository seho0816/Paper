def resolve_signup(
    _root,
    info,
    email: str,
    password_hash: str,
) -> dict:
    account = info.context.accounts.create({
        "email": email,
        "password_hash": password_hash,
        "role": "user",
    })

    return {
        "account_id": account["id"],
    }
