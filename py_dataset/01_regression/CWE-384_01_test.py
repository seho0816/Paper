from flask import request


def login():
    session_id = request.cookies.get(
        "session_id",
    )
    username = request.form["username"]
    password = request.form["password"]

    if not verify_credentials(
        username,
        password,
    ):
        return {
            "authenticated": False,
        }, 401

    bind_session_to_user(
        session_id,
        username,
    )

    return {
        "authenticated": True,
    }
