def build_session_cookie(
    session_id: str,
) -> str:
    return (
        f"session_id={session_id}; "
        "Path=/; HttpOnly; SameSite=Lax"
    )
