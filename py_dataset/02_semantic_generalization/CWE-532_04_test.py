import logging

logger = logging.getLogger(
    "recovery"
)


def issue_reset_link(
    email: str,
    token: str,
) -> None:
    logger.info(
        "password reset email=%s token=%s",
        email,
        token,
    )
    send_reset_email(
        email,
        token,
    )
