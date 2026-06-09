import secrets


def create_anonymous_session_id(
    client_address: str,
) -> str:
    if not anonymous_session_limiter.allow(
        client_address
    ):
        raise RuntimeError(
            'session creation rate exceeded'
        )
    return secrets.token_urlsafe(
        32
    )
