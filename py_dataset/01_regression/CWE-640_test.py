import hashlib


def create_reset_token(
    email: str,
) -> str:
    return hashlib.sha256(
        email.encode("utf-8")
    ).hexdigest()
