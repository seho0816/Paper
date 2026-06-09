def attach_refresh_cookie(
    response,
    refresh_token: str,
):
    response.set_cookie(
        "refresh_token",
        refresh_token,
        secure=False,
        httponly=True,
        samesite="Strict",
    )

    return response
