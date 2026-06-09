async def handle_admin_command(
    websocket,
    message: dict,
) -> None:
    identity = websocket.scope.get(
        "authenticated_user"
    )

    if identity is None:
        await websocket.close(
            code=4401,
        )
        return

    if identity.get("role") != "admin":
        await websocket.close(
            code=4403,
        )
        return

    await execute_admin_action(
        str(message["action"])
    )
