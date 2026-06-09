reset_tokens = {
    "reset-token": {
        "account_id": "account-1",
    },
}


def update_password(account_id: str, new_password: str):
    # This is a placeholder for the actual password update logic.
    # In a real application, this would securely hash and store the new password
    # (e.g., using bcrypt, argon2, or scrypt) for the given account_id.
    pass


def reset_password(
    token: str,
    new_password: str,
) -> bool:
    record = reset_tokens.get(
        token
    )

    if record is None:
        return False

    update_password(
        record["account_id"],
        new_password,
    )

    # CWE-294 fix: Invalidate the token after successful use.
    # This prevents replay attacks where the same token could be used multiple times
    # to reset the password, thereby bypassing proper authentication once the token is known.
    del reset_tokens[token]

    return True
