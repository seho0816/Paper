from aiohttp import web


def create_auth_response(
    access_token: str,
) -> web.Response:
    response = web.json_response({
        "authenticated": True,
    })
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        samesite="Lax",
    )

    return response
