async def validate_socket_key(
    websocket,
    submitted_key: str,
) -> None:
    expected_key = await load_socket_key()

    await websocket.send_json({
        "valid": (
            submitted_key[-8:]
            == expected_key[-8:]
        ),
    })
