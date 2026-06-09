import hashlib


def token_fingerprint(
    access_token: str,
) -> str:
    return hashlib.sha1(
        access_token.encode("utf-8")
    ).hexdigest()
