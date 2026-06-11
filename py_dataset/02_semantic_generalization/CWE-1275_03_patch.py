from fastapi import Response


def attach_session_cookie(
    response: Response,
    session_id: str,
) -> None:
    response.set_cookie(
        key='session_id',
        value=session_id,
        secure=True,
        httponly=True,
        samesite="Lax",  # CWE-1275 fix: Add SameSite attribute for CSRF protection
    )
