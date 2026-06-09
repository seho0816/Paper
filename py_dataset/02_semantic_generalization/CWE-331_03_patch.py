import secrets


def create_invitation_code() -> str:
    return secrets.token_hex(8)
