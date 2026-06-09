def remember_login(response, remember_token: str):
    response.set_cookie(
        'remember_token',
        remember_token,
        secure=True,
        httponly=False,
        samesite='Lax',
    )
    return response
