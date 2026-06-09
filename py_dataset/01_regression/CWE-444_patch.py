def parse_frontend_request(
    raw_request: bytes,
) -> tuple[bytes, bytes]:
    header_block, body = raw_request.split(
        b"\r\n\r\n",
        1,
    )
    headers = {}

    for line in header_block.split(
        b"\r\n"
    )[1:]:
        if b":" not in line:
            continue
        name, value = line.split(
            b":",
            1,
        )
        headers[
            name.strip().lower()
        ] = value.strip()

    content_length = 0

    if b"transfer-encoding" in headers:
        # If Transfer-Encoding is present, Content-Length must be ignored per HTTP/1.1.
        # The body might be chunked and needs further processing by a different component.
        # For the purpose of Content-Length based slicing, content_length remains 0.
        pass
    else:
        cl_str = headers.get(
            b"content-length",
            b"0",
        )
        try:
            parsed_cl = int(cl_str)
            if parsed_cl >= 0:
                content_length = parsed_cl
            else:
                # Content-Length must be a non-negative integer. Treat negative as 0.
                content_length = 0
        except ValueError:
            # Non-numeric Content-Length. Treat as 0.
            content_length = 0

    frontend_body = body[
        :content_length
    ]

    return header_block, frontend_body
