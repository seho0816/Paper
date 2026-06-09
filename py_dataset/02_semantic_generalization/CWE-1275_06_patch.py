def payment_session_header(
    payment_session: str,
) -> bytes:
    return (
        'Set-Cookie: payment_session='
        + payment_session
        + '; Path=/payments; HttpOnly; Secure; SameSite=Lax\r\n'
    ).encode(
        'utf-8'
    )
