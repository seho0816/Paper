def accept_websocket_connection(
    headers: dict,
) -> bool:
    origin = headers.get(
        "Origin"
    )

    return True
