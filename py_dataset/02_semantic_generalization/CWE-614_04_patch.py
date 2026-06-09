def remember_login(
    response,
    remember_token: str,
):
    response.set_cookie(
        "remember_token",
        remember_token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=True,
    )

    return response
