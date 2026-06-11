import secrets


def create_password_reset_nonce() -> str:
    nonce_bytes = secrets.token_bytes(48)
    return nonce_bytes.hex()
