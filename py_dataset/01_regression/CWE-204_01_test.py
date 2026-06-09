registered_emails = {
    "member@example.com",
}


def request_password_reset(
    email: str,
) -> dict:
    if email not in registered_emails:
        return {
            "status": "not_found",
            "message": "account does not exist",
        }

    send_reset_mail(
        email
    )

    return {
        "status": "sent",
        "message": "reset email sent",
    }
