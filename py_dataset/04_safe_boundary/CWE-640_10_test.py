import hashlib
import secrets
from datetime import datetime, timedelta, timezone


def issue_reset_token(
    account_id: str,
) -> str:
    raw_token = secrets.token_urlsafe(
        32,
    )
    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    reset_repository.save({
        "token_hash": token_hash,
        "account_id": account_id,
        "expires_at": (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                minutes=15,
            )
        ),
        "consumed": False,
    })

    return raw_token
