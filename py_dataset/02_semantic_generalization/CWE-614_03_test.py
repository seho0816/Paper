from fastapi import Response


def create_login_response(
    response: Response,
    session_token: str,
) -> dict:
    response.set_cookie(
        key="session",
        value=session_token,
        httponly=True,
        samesite="lax",
    )

    return {
        "authenticated": True,
    }
