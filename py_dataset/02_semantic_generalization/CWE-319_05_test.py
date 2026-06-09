import websocket


def connect_notifications(
    session_token: str,
):
    return websocket.create_connection(
        "ws://notifications.example.com/socket"
        f"?token={session_token}"
    )
