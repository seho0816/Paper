import logging

logger = logging.getLogger(
    "authentication"
)


def sanitize_log_value(
    value: str,
) -> str:
    return value.replace(
        "\r",
        "\\r",
    ).replace(
        "\n",
        "\\n",
    )


def record_login_attempt(
    username: str,
) -> None:
    logger.info(
        "login attempt username=%s",
        sanitize_log_value(username),
    )
