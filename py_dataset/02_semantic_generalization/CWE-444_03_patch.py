def forward_request(
    method: bytes,
    path: bytes,
    headers: list[tuple[bytes, bytes]],
    decoded_body: bytes,
) -> bytes:
    # Filter out any existing Content-Length or Transfer-Encoding headers.
    # This prevents HTTP Request Smuggling (CWE-444) by ensuring that only
    # a single, correctly calculated Content-Length header determines the body's length.
    filtered_headers = []
    for name, value in headers:
        # Perform case-insensitive comparison for standard HTTP header names.
        if name.lower() not in (b"content-length", b"transfer-encoding"):
            filtered_headers.append((name, value))

    # Calculate the actual content length of the decoded body.
    # Add a Content-Length header with this precise value.
    # This eliminates ambiguity in how different HTTP entities might interpret
    # the request body's length, which is crucial for preventing smuggling attacks.
    content_length_value = str(len(decoded_body)).encode('ascii')
    filtered_headers.append((b"Content-Length", content_length_value))

    header_block = b"\r\n".join(
        name + b": " + value
        for name, value in filtered_headers
    )

    return (
        method
        + b" "
        + path
        + b" HTTP/1.1\r\n"
        + header_block
        + b"\r\n\r\n"
        + decoded_body
    )
