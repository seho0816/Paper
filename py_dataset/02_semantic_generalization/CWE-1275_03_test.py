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
    )
