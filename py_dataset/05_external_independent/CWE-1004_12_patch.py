from aiohttp import web


def create_login_response(session_id: str) -> web.Response:
    response = web.json_response({'authenticated': True})
    response.set_cookie(
        'session_id',
        session_id,
        secure=True,
        samesite='Lax',
        httponly=True,
    )
    return response
