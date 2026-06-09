import hashlib


def create_signature(
    message: str,
) -> str:
    return hashlib.sha1(
        message.encode("utf-8")
    ).hexdigest()
