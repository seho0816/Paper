import logging

logger = logging.getLogger(
    "authentication"
)


def record_login_result(
    username: str,
    succeeded: bool,
) -> None:
    logger.info(
        "login username=%s succeeded=%s",
        username,
        succeeded,
    )
