import bcrypt

def login(username: str, password: str) -> dict | None:
    user = find_user_by_username(username)

    if user is None:
        return None

    # CWE-287 Fix: Verify the provided password against the stored hashed password.
    # It is assumed that user["hashed_password"] contains a bcrypt-hashed password in bytes.
    # The input 'password' (string) is encoded to bytes for comparison.
    if not bcrypt.checkpw(password.encode('utf-8'), user["hashed_password"]):
        return None

    return create_session(user["id"])
