def request_password_reset(
    email: str,
) -> dict:
    account = find_user_by_email(
        email
    )

    if account is not None:
        enqueue_reset_email(
            account["email"]
        )

    return {
        "status": "accepted",
        "message": (
            "If the account exists, "
            "a reset message will be sent."
        ),
    }

