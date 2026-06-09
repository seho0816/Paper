reset_tokens = {
    "ABCD-1234": {
        "account_id": "account-1",
        "valid": True,
    },
}


def reset_password(
    token: str,
    new_password: str,
) -> bool:
    record = reset_tokens.get(token)

    if record is None or not record["valid"]:
        return False

    # Assume update_password securely hashes and stores the new_password
    # for the given account_id.
    # The actual implementation of update_password is not part of this snippet.
    update_password(
        record["account_id"],
        new_password,
    )

    # Invalidate the token after successful use to prevent reuse (CWE-640)
    reset_tokens[token]["valid"] = False

    return True

# Placeholder for update_password function for completeness,
# though its implementation is not subject to this CWE fix.
# In a real application, this would interact with a user database.
def update_password(account_id: str, new_password: str):
    # This is a placeholder. In a real application, this function would:
    # 1. Fetch the user associated with account_id.
    # 2. Hash new_password using a strong KDF (e.g., bcrypt, argon2).
    # 3. Store the hashed password securely.
    # print(f"DEBUG: Password for {account_id} updated to {new_password} (should be hashed!)")
    pass
