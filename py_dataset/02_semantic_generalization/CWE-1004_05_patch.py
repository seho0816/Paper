def administrator_cookie(admin_session: str) -> bytes:
    header = (
        'Set-Cookie: admin_session='
        + admin_session
        + '; Path=/admin; Secure; SameSite=Strict; HttpOnly\r\n'
    )
    return header.encode('utf-8')
