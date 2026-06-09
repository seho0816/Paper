from flask import make_response


def refresh_response(
    refresh_token: str,
):
    response = make_response({
        'refreshed': True,
    })
    response.set_cookie(
        'refresh_token',
        refresh_token,
        secure=True,
        httponly=True,
    )
    return response
