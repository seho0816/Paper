import secrets


def create_api_token() -> str:
    return secrets.token_hex(
        32
    )
