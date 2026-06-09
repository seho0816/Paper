async def disconnect_socket(
    websocket,
    reconnect_token: str,
) -> None:
    await websocket.close(
        code=1000,
    )
    record_disconnect(
        reconnect_token
    )
