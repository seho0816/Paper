from flask import make_response


def login_response(access_token: str):
    response = make_response({'authenticated': True})
    response.set_cookie(
        'access_token',
        access_token,
        secure=True,
        httponly=True,
        samesite='Lax',
    )
    return response
