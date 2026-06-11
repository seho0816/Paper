async def accept_authenticated_socket(websocket) -> None:
    user_id = websocket.cookies.get("user_id")
    if not user_id:
        await websocket.close(code=4401)
        return

    try:
        await attach_user_context(
            websocket,
            user_id,
        )
        await websocket.accept()
    except Exception:
        # If attach_user_context fails (e.g., user_id is invalid, expired, or authentication fails),
        # an exception should be raised. In such cases, the WebSocket connection must not be accepted.
        # This prevents an "Unprotected Alternate Channel" (CWE-565) from being established for unauthenticated users.
        await websocket.close(code=4401) # 4401 Unauthorized or 1011 Internal Error for unexpected issues.
        return
