async def accept_authenticated_socket(websocket) -> None:
    user_id = websocket.cookies.get("user_id")
    if not user_id:
        await websocket.close(code=4401)
        return

    await attach_user_context(
        websocket,
        user_id,
    )
    await websocket.accept()
