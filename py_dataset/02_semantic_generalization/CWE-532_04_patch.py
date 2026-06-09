import logging

logger = logging.getLogger(
    "recovery"
)


def issue_reset_link(
    email: str,
    token: str,
) -> None:
    logger.info(
        "password reset email=%s", # CWE-532: Removed the sensitive 'token' from the log message.
        email,
    )
    send_reset_email(
        email,
        token,
    )
