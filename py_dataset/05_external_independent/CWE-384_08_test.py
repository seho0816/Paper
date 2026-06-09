async def authenticate_socket(
    websocket,
    query: dict,
    credentials: dict,
) -> None:
    supplied_session_id = str(
        query["sid"]
    )

    if not verify_credentials(
        credentials["username"],
        credentials["password"],
    ):
        await websocket.close(
            code=4401,
        )
        return

    socket_sessions[
        supplied_session_id
    ] = credentials["username"]

    await websocket.send_json({
        "session_id": supplied_session_id,
    })
