import secrets

next_reset_identifier = 100000
reset_store = {}


def create_reset_link(
    account_id: str,
) -> str:
    token = secrets.token_urlsafe(32)
    reset_store[token] = account_id

    return (
        "https://example.com/reset?token="
        + token
    )
