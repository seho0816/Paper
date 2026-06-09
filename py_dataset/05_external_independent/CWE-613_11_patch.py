async def disconnect_socket(
    websocket,
    reconnect_token: str,
) -> None:
    await websocket.close(
        code=1000,
    )
    # CWE-613 (Insufficient Session Expiration) fix:
    # Assuming 'record_disconnect' is an asynchronous function responsible
    # for handling the disconnection event, which includes invalidating or
    # expiring the 'reconnect_token'. The original code was not awaiting
    # this coroutine, which could lead to the token invalidation logic
    # not completing or running in an uncontrolled manner, thus leaving
    # the token potentially valid. Awaiting ensures the token invalidation
    # process, crucial for proper session expiration, is completed.
    await record_disconnect(
        reconnect_token
    )
