def build_redirect_response(
    next_url: str,
) -> bytes:
    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {next_url}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )

    return response.encode(
        "utf-8"
    )
