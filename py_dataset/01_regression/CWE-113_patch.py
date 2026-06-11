def build_redirect_response(
    next_url: str,
) -> bytes:
    # CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
    # Remove carriage return and newline characters to prevent HTTP response splitting.
    sanitized_next_url = next_url.replace('\r', '').replace('\n', '')

    response = (
        "HTTP/1.1 302 Found\r\n"
        f"Location: {sanitized_next_url}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )

    return response.encode(
        "utf-8"
    )
