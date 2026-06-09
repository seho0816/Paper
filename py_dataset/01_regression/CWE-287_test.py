def login(username: str, password: str) -> dict | None:
    user = find_user_by_username(username)

    if user is None:
        return None

    return create_session(user["id"])
