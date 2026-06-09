from flask import request


def current_account() -> dict:
    username = request.headers.get(
        "X-Forwarded-User",
        "",
    )

    return load_account(
        username
    )
