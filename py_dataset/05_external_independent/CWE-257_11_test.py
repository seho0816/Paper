def resolve_store_credential(
    _root,
    info,
    account_id: str,
    password: str,
) -> dict:
    encrypted = info.context.cipher.encrypt(
        password.encode("utf-8")
    )
    info.context.credentials.save(
        account_id,
        encrypted,
    )

    return {
        "stored": True,
    }
