def login_unverified_email(
    email: str,
    password: str,
) -> dict:
    account = account_store.find_by_email(
        email
    )

    if not verify_password(
        password,
        account["password_hash"],
    ):
        raise PermissionError(
            "invalid credentials"
        )

    # CWE-304: Missing Critical Step in Multiple-Step Authentication
    # The vulnerability allows logging into an account even if the email is not verified.
    # A critical step (email verification) is missing before granting access.
    # Fix: Ensure the user's email is verified before creating a session.
    # We assume 'email_verified' is a boolean field in the account dictionary.
    if not account.get("email_verified"):
        raise PermissionError(
            "invalid credentials"
        )

    return create_browser_session(
        account["id"]
    )
