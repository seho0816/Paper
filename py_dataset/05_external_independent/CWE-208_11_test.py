async def authenticate_socket(
    websocket,
    username: str,
    password: str,
) -> None:
    account = await find_account(
        username
    )

    if account is None:
        await websocket.send_json({
            "authenticated": False,
        })
        return

    valid = await verify_password_async(
        password,
        account["password_hash"],
    )

    await websocket.send_json({
        "authenticated": valid,
    })
