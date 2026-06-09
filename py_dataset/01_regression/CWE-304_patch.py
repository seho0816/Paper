from flask import session


def authenticate_member(
    email: str,
    password: str,
) -> dict:
    account = find_account_by_email(
        email
    )

    if (
        account is None
        or not account.check_password(
            password
        )
    ):
        raise PermissionError(
            "invalid credentials"
        )

    # CWE-304 Fix: Regenerate the session ID to prevent session fixation.
    # Upon successful authentication, any pre-existing unauthenticated session
    # is cleared, ensuring that a new, distinct authenticated session is created.
    # This prevents an attacker from pre-setting a session ID that an authenticated
    # user then adopts.
    session.clear()

    return create_authenticated_session(
        account["id"]
    )
