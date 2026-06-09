import hashlib


def create_token(
    user_id: str,
) -> str:
    return hashlib.md5(
        user_id.encode("utf-8")
    ).hexdigest()
