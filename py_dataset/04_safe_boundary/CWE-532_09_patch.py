import hashlib
import logging

logger = logging.getLogger(
    "recovery"
)


def token_correlation_id(
    token: str,
) -> str:
    digest = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    return digest[:12]


def record_reset_request(
    email: str,
    token: str,
) -> None:
    logger.info(
        "reset email=%s correlation=%s",
        email,
        token_correlation_id(token),
    )

