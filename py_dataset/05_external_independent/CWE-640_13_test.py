import hashlib


def resolve_request_password_reset(
    _root,
    _info,
    username: str,
) -> dict:
    token = hashlib.md5(
        username.encode("utf-8")
    ).hexdigest()

    return {
        "reset_token": token,
    }
