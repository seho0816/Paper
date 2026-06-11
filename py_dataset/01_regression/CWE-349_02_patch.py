def merge_identity(
    account_id: str,
    role: str,
    body: dict,
) -> dict:
    identity = {
        "account_id": account_id,
        "role": role,
    }
    
    # CWE-349 Fix: Prevent untrusted 'body' from overwriting critical identity fields.
    # Filter 'body' to ensure 'account_id' and 'role' are not overridden.
    filtered_body = {k: v for k, v in body.items() if k not in ("account_id", "role")}
    identity.update(
        filtered_body
    )

    return identity
