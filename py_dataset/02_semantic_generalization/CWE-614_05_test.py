def administrator_cookie(
    admin_session_id: str,
) -> bytes:
    value = (
        "Set-Cookie: admin_session="
        + admin_session_id
        + "; Path=/admin; HttpOnly"
        + "; SameSite=Strict\r\n"
    )

    return value.encode(
        "utf-8"
    )
