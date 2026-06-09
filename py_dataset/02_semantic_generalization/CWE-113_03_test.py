def build_cookie_response(
    session_value: str,
) -> bytes:
    response = (
        "HTTP/1.1 200 OK\r\n"
        f"Set-Cookie: session={session_value}\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK"
    )

    return response.encode(
        "utf-8"
    )
