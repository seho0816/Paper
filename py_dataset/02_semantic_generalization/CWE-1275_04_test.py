def remember_login(
    response,
    token: str,
):
    response.set_cookie(
        'remember_token',
        token,
        secure=True,
        httponly=True,
        max_age=2592000,
    )
    return response
