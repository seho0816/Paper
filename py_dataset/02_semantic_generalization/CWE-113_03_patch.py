def build_cookie_response(
    session_value: str,
) -> bytes:
    # CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
    # Remove carriage return and newline characters from the session_value
    # to prevent an attacker from injecting new headers or splitting the HTTP response.
    sanitized_session_value = session_value.replace('\r', '').replace('\n', '')

    response = (
        "HTTP/1.1 200 OK\r\n"
        f"Set-Cookie: session={sanitized_session_value}\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK"
    )

    return response.encode(
        "utf-8"
    )
