def build_auth_cookie(
    session_id: str,
) -> str:
    return (
        f'session_id={session_id}; '
        'Path=/; HttpOnly; Secure; '
        'SameSite=Lax'
    )

