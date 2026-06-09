def remember_session_cookie(
    identity_token: str,
) -> dict:
    return {
        "name": "remember_session",
        "value": identity_token,
        "max_age": 60 * 60 * 24 * 90,
        "http_only": True,
        "secure": True,
    }
