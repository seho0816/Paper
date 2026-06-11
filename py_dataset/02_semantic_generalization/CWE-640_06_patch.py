import datetime

reset_tokens: dict[str, dict[str, str | datetime.datetime]] = {}


def current_time() -> datetime.datetime:
    return datetime.datetime.now()


TOKEN_EXPIRATION_MINUTES = 30


def save_reset_token(
    token: str,
    account_id: str,
) -> None:
    reset_tokens[token] = {
        "account_id": account_id,
        "created": current_time(),
    }


def verify_reset_token(
    token: str,
) -> str | None:
    record = reset_tokens.get(token)

    if record is None:
        return None

    created_time = record.get("created")
    account_id = record.get("account_id")

    if not isinstance(created_time, datetime.datetime) or not isinstance(account_id, str):
        # Remove malformed or unexpected records from storage
        del reset_tokens[token]
        return None

    # CWE-640 Fix: Check for token expiration
    # Tokens should have a limited lifetime to prevent their indefinite validity.
    if current_time() > created_time + datetime.timedelta(minutes=TOKEN_EXPIRATION_MINUTES):
        # Token has expired, remove it to prevent any further use and clean up storage.
        del reset_tokens[token]
        return None

    # CWE-640 Fix: Invalidate token after successful use
    # A password reset token should be a one-time use token.
    # Removing it immediately after verification prevents reuse.
    del reset_tokens[token]

    return account_id
