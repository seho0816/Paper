from aiohttp import web


def admin_login_response(
    admin_session: str,
) -> web.Response:
    response = web.json_response({
        'authenticated': True,
    })
    response.set_cookie(
        'admin_session',
        admin_session,
        secure=True,
        httponly=True,
        samesite='Strict',
    )
    return response
