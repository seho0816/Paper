def login(email: str, password: str) -> dict:
    user = find_user_by_email(email)

    if user is None:
        return {
            "success": False,
            "message": "email not registered",
        }

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return {
            "success": False,
            "message": "wrong password",
        }

    return {
        "success": True,
        "message": "login success",
    }
