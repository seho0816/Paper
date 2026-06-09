def resolve_signup(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    account = account_store.create({
        "email": email,
        "password": password,
    })

    return {
        "account_id": account["id"],
    }
