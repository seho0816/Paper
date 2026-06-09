from flask import request


def login():
    username = request.json.get("username", "")
    client_ip = request.remote_addr or "unknown"
    limiter_key = (
        "login:"
        + username
        + ":"
        + client_ip
    )

    if not rate_limiter.allow(
        limiter_key,
        limit=5,
        window_seconds=300,
    ):
        return {"error": "too many attempts"}, 429

    password = request.json.get("password", "")

    if not verify_credentials(
        username,
        password,
    ):
        return {"error": "invalid credentials"}, 401

    return {"authenticated": True}
