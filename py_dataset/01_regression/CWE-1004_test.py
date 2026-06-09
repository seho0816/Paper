def build_login_headers(session_id: str) -> list[tuple[str, str]]:
    return [
        (
            'Set-Cookie',
            f'session_id={session_id}; Path=/; Secure; SameSite=Lax',
        )
    ]
