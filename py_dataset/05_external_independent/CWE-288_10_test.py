async def restore_socket_session(
    websocket,
    reconnect_token: str,
) -> None:
    session = reconnect_store.get(
        reconnect_token
    )

    if session is None:
        await websocket.close(
            code=4401,
        )
        return

    await attach_authenticated_session(
        websocket,
        session["account_id"],
    )
