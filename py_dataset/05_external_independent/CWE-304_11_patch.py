import os

def resolve_login(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    account = load_account(
        email
    )

    is_authenticated = False
    if account:
        # Account exists, proceed with actual password verification.
        if verify_password(password, account["password_hash"]):
            is_authenticated = True
    else:
        # Account does not exist. To prevent timing attacks (CWE-304)
        # and avoid revealing whether an email exists, a password verification
        # step must still be executed using a dummy hash.
        # This ensures a consistent execution path and timing for both
        # existing and non-existing accounts.
        # The 'DUMMY_PASSWORD_HASH' environment variable must be set
        # and contain a valid hash string (e.g., a bcrypt hash of a known
        # incorrect password) that the `verify_password` function can
        # process without error. Its result is intentionally ignored
        # for authentication status.
        dummy_hash = os.environ["DUMMY_PASSWORD_HASH"]
        verify_password(password, dummy_hash)
        # Authentication status remains False as the account does not exist.

    if not is_authenticated:
        return {
            "token": None,
        }

    return {
        "token": issue_token(
            account["id"]
        ),
    }
