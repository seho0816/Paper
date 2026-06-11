def cross_site_session_cookie(
    session_id: str,
) -> str:
    return (
        f'session={session_id}; '
        'Path=/; HttpOnly; Secure; '
        'SameSite=Strict'
    )
