def merge_identity(
    account_id: str,
    role: str,
    body: dict,
) -> dict:
    identity = {
        "account_id": account_id,
        "role": role,
    }
    identity.update(
        body
    )

    return identity
