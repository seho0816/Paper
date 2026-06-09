import secrets
from datetime import datetime, timedelta, timezone


def issue_reset_code(
    user_id: str,
) -> str:
    # CWE-331: Insufficient Entropy in PRNG.
    # The original code generated a 6-digit number, providing only ~20 bits of entropy.
    # This is easily brute-forced for security-sensitive tokens like reset codes.
    # secrets.token_hex(32) generates a cryptographically strong random 64-character
    # hexadecimal string, providing 256 bits of entropy, which is sufficiently secure.
    code = secrets.token_hex(32)
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
