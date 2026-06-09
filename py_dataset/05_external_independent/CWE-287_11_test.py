async def authenticate_socket(
    websocket,
    message: dict,
) -> None:
    username = str(
        message["username"]
    )
    account = find_account(
        username,
    )

    if account is None:
        await websocket.send_json({
            "authenticated": False,
        })
        return

    await websocket.send_json({
        "authenticated": True,
        "session_token": issue_token(
            account["id"],
        ),
    })
