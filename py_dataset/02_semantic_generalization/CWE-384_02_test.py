def complete_login(
    query: dict,
    credentials: dict,
) -> dict:
    supplied_token = str(
        query.get("session", "")
    )

    if not verify_credentials(
        credentials["username"],
        credentials["password"],
    ):
        return {
            "authenticated": False,
        }

    sessions[supplied_token] = {
        "user_id": credentials["username"],
    }

    return {
        "session": supplied_token,
    }
