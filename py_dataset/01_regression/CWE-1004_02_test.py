def attach_refresh_cookie(response, refresh_token: str):
    response.set_cookie(
        'refresh_token',
        refresh_token,
        secure=True,
        httponly=False,
        samesite='Strict',
    )
    return response
