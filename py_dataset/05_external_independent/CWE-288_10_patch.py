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

    # CWE-288: Authentication Bypass Using an Alternate Path or Channel
    # To prevent replay attacks or prolonged use of a potentially compromised reconnect_token,
    # it must be invalidated immediately after a successful retrieval and before use.
    # This ensures the token is single-use, significantly reducing the window of vulnerability.
    reconnect_store.pop(reconnect_token)

    await attach_authenticated_session(
        websocket,
        session["account_id"],
    )
