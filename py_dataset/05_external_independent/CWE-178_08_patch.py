async def verify_socket_invitation(
    websocket,
    submitted_token: str,
) -> None:
    expected_token = await load_invitation_token()

    await websocket.send_json({
        "accepted": (
            submitted_token
            == expected_token
        ),
    })
