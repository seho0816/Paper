import urllib.parse

def build_auth_cookie(
    session_id: str,
) -> str:
    encoded_session_id = urllib.parse.quote(session_id)
    return (
        f'session_id={encoded_session_id}; '
        'Path=/; HttpOnly; Secure'
    )
