import secrets


def create_reset_token() -> str:
    return secrets.token_urlsafe(
        32
    )

