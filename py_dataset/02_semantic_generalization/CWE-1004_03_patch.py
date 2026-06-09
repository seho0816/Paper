from fastapi import Response


def set_session_cookie(response: Response, session_token: str) -> None:
    response.set_cookie(
        key='session',
        value=session_token,
        secure=True,
        samesite='lax',
        httponly=True,
    )
