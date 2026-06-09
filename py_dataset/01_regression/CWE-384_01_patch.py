import uuid
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

    # After successful authentication, generate a new session ID to prevent
    # session fixation (CWE-384). This ensures that an attacker cannot
    # pre-set a session ID that gets re-used for an authenticated session.
    newly_generated_session_id = str(uuid.uuid4())

    bind_session_to_user(
        newly_generated_session_id,  # Use the newly generated session ID
        username,
    )

    return {
        "authenticated": True,
    }
