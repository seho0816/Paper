def emergency_access(
    token: str,
    target_account_id: str,
) -> str | None:
    record = emergency_tokens.get(
        token
    )

    if record is None:
        return None

    return create_session(
        target_account_id
    )
