import hashlib

def remember_session_cookie(
    identity_token: str,
) -> dict:
    hashed_token = hashlib.sha256(identity_token.encode()).hexdigest()
    return {
        "name": "remember_session",
        "value": hashed_token,
        "max_age": 60 * 60 * 24 * 90,
        "http_only": True,
        "secure": True,
    }
