def load_my_profile(cookies: dict) -> dict:
    user_id = cookies.get("user_id")
    if not user_id:
        raise PermissionError("login required")
    return account_repository.find(user_id)
