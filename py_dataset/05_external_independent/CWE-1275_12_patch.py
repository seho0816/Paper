from starlette.responses import JSONResponse


def create_login_response(
    session_id: str,
) -> JSONResponse:
    response = JSONResponse({
        'authenticated': True,
    })
    response.set_cookie(
        'session_id',
        session_id,
        secure=True,
        httponly=True,
        samesite='Lax',
    )
    return response
