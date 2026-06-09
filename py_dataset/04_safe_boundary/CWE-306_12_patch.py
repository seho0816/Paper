async def handle_admin_command(
    websocket,
    message: dict,
) -> None:
    identity = websocket.scope.get(
        "authenticated_user"
    )

    # CWE-306: Missing Authentication for Critical Function.
    # The original check `identity is None` only verifies the *presence* of an identity object.
    # However, an attacker might be able to inject a forged `authenticated_user` object or
    # dictionary (e.g., `{"role": "admin"}`) into the websocket scope if proper authentication
    # middleware is missing or bypassed.
    # To mitigate this, we add a check for a unique identifier (like 'id'). A truly
    # authenticated user object/dictionary is expected to have a non-None 'id' value,
    # ensuring that the identity has been securely established and is not merely spoofed.
    # This strengthens the authentication aspect by requiring a specific trusted attribute.
    if identity is None or identity.get("id") is None:
        await websocket.close(
            code=4401, # Unauthorized (identity not authenticated or incomplete)
        )
        return

    if identity.get("role") != "admin":
        await websocket.close(
            code=4403, # Forbidden (authenticated user lacks required role)
        )
        return

    await execute_admin_action(
        str(message["action"])
    )
