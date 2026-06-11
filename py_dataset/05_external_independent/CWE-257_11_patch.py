import bcrypt

def resolve_store_credential(
    _root,
    info,
    account_id: str,
    password: str,
) -> dict:
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    info.context.credentials.save(
        account_id,
        hashed_password,
    )

    return {
        "stored": True,
    }
