import secrets
from datetime import datetime, timedelta, timezone


def issue_otp(
    account_id: str,
) -> str:
    code = (
        f"{secrets.randbelow(100_000_000):08d}"
    )
    save_otp({
        "account_id": account_id,
        "code_hash": hash_code(
            code
        ),
        "expires_at": (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                minutes=3,
            )
        ),
        "max_attempts": 5,
    })

    return code
