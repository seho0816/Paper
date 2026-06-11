registered_emails = {
    "member@example.com",
}


def request_password_reset(
    email: str,
) -> dict:
    # Do not reveal whether the email exists or not to prevent user enumeration (CWE-204).
    # Always return a generic success message, regardless of whether the email is registered.
    if email in registered_emails:
        # Only attempt to send a reset mail if the email is actually registered.
        # The 'send_reset_mail' function is assumed to be defined elsewhere.
        send_reset_mail(
            email
        )

    return {
        "status": "sent",
        "message": "reset email sent",
    }
