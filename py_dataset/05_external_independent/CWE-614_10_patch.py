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
        secure=True,  # CWE-614 fix: Ensure the cookie is only sent over HTTPS.
    )

    return response
