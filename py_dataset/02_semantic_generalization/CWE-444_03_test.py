def forward_request(
    method: bytes,
    path: bytes,
    headers: list[tuple[bytes, bytes]],
    decoded_body: bytes,
) -> bytes:
    header_block = b"\r\n".join(
        name + b": " + value
        for name, value in headers
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
