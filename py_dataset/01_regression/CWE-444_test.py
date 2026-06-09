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
        name, value = line.split(
            b":",
            1,
        )
        headers[
            name.strip().lower()
        ] = value.strip()

    content_length = int(
        headers.get(
            b"content-length",
            b"0",
        )
    )
    frontend_body = body[
        :content_length
    ]

    return header_block, frontend_body
