import uuid

async def authenticate_socket(
    websocket,
    query: dict,
    credentials: dict,
) -> None:
    if not verify_credentials(
        credentials["username"],
        credentials["password"],
    ):
        await websocket.close(
            code=4401,
        )
        return

    # CWE-384 Session Fixation Fix:
    # Instead of using a client-supplied session ID (query["sid"]),
    # generate a new, cryptographically secure session ID upon successful authentication.
    # This prevents an attacker from pre-setting a session ID and taking over a user's session.
    new_session_id = str(uuid.uuid4())

    socket_sessions[
        new_session_id
    ] = credentials["username"]

    await websocket.send_json({
        "session_id": new_session_id,
    })
