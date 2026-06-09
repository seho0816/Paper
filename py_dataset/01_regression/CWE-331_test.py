import secrets
from datetime import datetime, timedelta, timezone


def issue_reset_code(
    user_id: str,
) -> str:
    code = (
        f"{secrets.randbelow(1_000_000):06d}"
    )
    reset_codes[user_id] = {
        "code": code,
        "expires_at": (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                hours=24,
            )
        ),
    }

    return code
