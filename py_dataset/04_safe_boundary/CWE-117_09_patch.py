import logging
import re

logger = logging.getLogger(
    "account"
)
ACCOUNT_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,64}$"
)


def log_account_access(
    account_id: str,
) -> None:
    if not ACCOUNT_ID_PATTERN.fullmatch(
        account_id,
    ):
        raise ValueError(
            "invalid account identifier"
        )

    logger.info(
        "account access id=%s",
        account_id,
    )

