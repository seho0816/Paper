from starlette.responses import JSONResponse


def create_session_response(
    session_id: str,
) -> JSONResponse:
    response = JSONResponse({
        "authenticated": True,
    })
    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        samesite="lax",
    )

    return response
