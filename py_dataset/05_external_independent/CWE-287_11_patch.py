import bcrypt

async def authenticate_socket(
    websocket,
    message: dict,
) -> None:
    username = str(
        message["username"]
    )
    # Extract the password from the message
    password = message.get("password")

    # If no password is provided, authentication fails
    if not password:
        await websocket.send_json({
            "authenticated": False,
        })
        return

    account = find_account(
        username,
    )

    if account is None:
        await websocket.send_json({
            "authenticated": False,
        })
        return

    # Retrieve the stored hashed password from the account
    stored_hashed_password = account.get("hashed_password")

    # If no hashed password is found, authentication fails
    if not stored_hashed_password:
        await websocket.send_json({
            "authenticated": False,
        })
        return

    # Verify the provided password against the stored hashed password using bcrypt
    # bcrypt.checkpw expects both arguments to be bytes
    try:
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            await websocket.send_json({
                "authenticated": False,
            })
            return
    except ValueError:
        # Handle cases where the stored_hashed_password might be malformed or invalid bcrypt hash
        await websocket.send_json({
            "authenticated": False,
        })
        return

    # If we reach here, the username exists and the password matches
    await websocket.send_json({
        "authenticated": True,
        "session_token": issue_token(
            account["id"],
        ),
    })
