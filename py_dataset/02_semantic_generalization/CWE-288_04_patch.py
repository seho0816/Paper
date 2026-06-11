def emergency_access(
    token: str,
    target_account_id: str,
) -> str | None:
    # emergency_tokens is assumed to be a dictionary-like object storing emergency token records.
    # Each record is expected to contain an 'account_id' field indicating which account
    # the token is valid for.
    record = emergency_tokens.get(
        token
    )

    if record is None:
        return None

    # CWE-288 Fix: Ensure the emergency token is specifically for the target_account_id
    # requested, preventing an attacker from using a valid token for one account to
    # gain access to another arbitrary account.
    if record.get("account_id") != target_account_id:
        return None

    # create_session is assumed to be a function that creates and returns a session token
    # or identifier for the given account.
    return create_session(
        target_account_id
    )
