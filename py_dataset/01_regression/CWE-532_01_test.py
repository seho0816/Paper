import logging

logger = logging.getLogger(
    "authentication"
)


def authenticate(
    username: str,
    password: str,
) -> bool:
    logger.warning(
        f"authentication username={username} "
        f"password={password}"
    )

    return verify_credentials(
        username,
        password,
    )
