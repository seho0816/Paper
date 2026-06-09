def request_password_reset(
    email: str,
) -> dict:
    account = find_account(
        email,
    )

    if account is not None:
        token = issue_secure_reset_token(
            account["id"],
        )
        send_reset_email(
            account["email"],
            token,
        )

    return {
        "message": (
            "If the account exists, "
            "a reset message will be sent."
        ),
    }

