import bcrypt

def authenticate(email: str, submitted_password: str) -> str | None:
    account = find_account_by_email(email)

    if account is None:
        return None

    # CWE-287 Fix: Verify the submitted password against the stored hashed password.
    stored_hashed_password = account.get("hashed_password")

    # If no hashed password is found or account data is malformed, authentication fails.
    if stored_hashed_password is None:
        return None

    # Ensure submitted_password is in bytes for bcrypt.checkpw comparison.
    if isinstance(submitted_password, str):
        submitted_password_bytes = submitted_password.encode('utf-8')
    elif isinstance(submitted_password, bytes):
        submitted_password_bytes = submitted_password
    else:
        # Invalid type for submitted_password, fail authentication.
        return None

    # Ensure stored_hashed_password is in bytes for bcrypt.checkpw comparison.
    # It is recommended to store password hashes directly as bytes.
    if isinstance(stored_hashed_password, str):
        stored_hashed_password_bytes = stored_hashed_password.encode('utf-8')
    elif isinstance(stored_hashed_password, bytes):
        stored_hashed_password_bytes = stored_hashed_password
    else:
        # Invalid type for stored_hashed_password, fail authentication.
        return None

    # Compare the submitted password with the stored hash.
    if bcrypt.checkpw(submitted_password_bytes, stored_hashed_password_bytes):
        return issue_access_token(
            account["account_id"],
        )
    else:
        # Passwords do not match, authentication fails.
        return None
